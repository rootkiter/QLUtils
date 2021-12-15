#!/bin/python
###############################################
# File Name : Recombine.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-11 11:04:28 CST
###############################################

import json
from qiling.os.memory import QlMemoryHeap
from collections import namedtuple
from .ql_util_methods import get_util_gadgets
from .Gadget import *

class RcbnArchive:
    def __init__(self):
        self.archive_result = {}
        self.num_stack = []
        self.lastres = None

    def lastresult(self, lastresult):
        self.lastres = lastresult

    def push_num(self, number):
        self.num_stack.append(number)

    def pop_num(self):
        return self.num_stack.pop()

    def list_archive(self, key, item):
        if key not in self.archive_result:
            self.archive_result[key] = []
        elif type(self.archive_result[key]) is not list:
            print("list_archive exception, not right type")
            return
        self.archive_result[key].append(item)

    def archive(self, key, value):
        self.archive_result[key] = value

    def get_archive(self, key):
        if key not in self.archive_result:
            return None
        return self.archive_result[key]

    def __str__(self):
        return json.dumps(self.archive_result)

def arch_gadget_callback(qlkit, gdt, result, gdt_data):
    (serial, rcbnArchive, user_callback, userdata) = gdt_data
    ret = None
    if user_callback != None and gdt.need_callback:
        ret = user_callback(qlkit, serial, gdt, result, rcbnArchive, userdata)
    rcbnArchive.lastresult(result)
    return ret

def process_the_gadget(
    qlkit, serial, gdt, quitaddr, rcbnArchive, user_callback, userdata
):
    if isinstance(gdt, EXIT):
        qlkit.reg.arch_pc = gdt.quit_pc
        serial = 99999

    if isinstance(gdt, BuiltInGadgetAbs):
        resmap = gdt.runit(qlkit, rcbnArchive)
        current_result = namedtuple("current_result", list(resmap))
        result = current_result(**resmap)
        if user_callback != None:
            user_callback(qlkit, serial, gdt, result, rcbnArchive, userdata)
        rcbnArchive.lastresult(result)
    elif isinstance(gdt, MonitorGadgetAbs):
        resmap = gdt.ql_install(
            qlkit, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )
    elif isinstance(gdt, MonitorMemAbs):
        gdt.hook_install(
            qlkit, rcbnArchive, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )
    elif isinstance(gdt, DynHookAbs):
        gdt.ql_install(
            qlkit, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )
    elif isinstance(gdt, SyscallPatchAbs):
        gdt.ql_install(
            qlkit, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )
    elif isinstance(gdt, HookFunctionAbs):
        gdt.ql_install(
            qlkit, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )
    elif isinstance(gdt, ArchGadgetAbs):
        argslist = []
        for i in range(0, gdt.arg_need()):
            num = rcbnArchive.pop_num()
            argslist.append(num)
        start_addr = gdt.install_hook_callback(
            qlkit, argslist, quitaddr, arch_gadget_callback,
            (serial, rcbnArchive, user_callback, userdata)
        )

        qlkit.reg.arch_pc = start_addr


def on_each_gdt(qlkit, addr, gdtarg):
    serial, lastgdt, gdt, nextaddr, rcbnresult, user_callback, userdata= gdtarg
    gdt.start_trigger()
    if lastgdt != None:
        lastgdt.stop_trigger()
    process_the_gadget(
        qlkit, serial, gdt, nextaddr, rcbnresult, user_callback, userdata
    )

class Recombine:
    def __init__(self, qlkit, rcbnarchive):
        self.qlkit   = qlkit
        self.gadgets = None
        self.cflow_start = None
        self.cflow_end   = None
        self.result  = rcbnarchive

    def asm_build(self, startaddr, codestr):
        asmbin, num = self.qlkit.assembler.asm(codestr)
        nextaddr = len(asmbin) + startaddr
        return (startaddr, nextaddr, asmbin)

    def top_cflow_prepare(self, quit_addr, user_callback, userdata):
        new_gadgets = self.gadgets + [EXIT(quit_addr)]

        top_cflow_size  = (len(new_gadgets)) * 8
        top_cflow_start = self.qlkit.mem_align_alloc(top_cflow_size)

        cur_start = top_cflow_start
        asm_code_list = []

        for serial in range(0, len(new_gadgets)):
            gdt = new_gadgets[serial]
            cur_addr, nextaddr, asmbin = self.asm_build(
                cur_start, "nop"
            )
            asm_code_list.append((serial, cur_start, asmbin, gdt, nextaddr))
            cur_start = nextaddr

        lastgdt = None
        for serial, addr, asmbin, gdt, nextaddr in asm_code_list:
            self.qlkit.mem.write(addr, bytes(asmbin))
            self.qlkit.my_hook_code(
                addr, on_each_gdt,
                (serial, lastgdt, gdt, nextaddr, self.result, user_callback, userdata)
            )
            lastgdt = gdt

        return top_cflow_start, nextaddr

    def run_env_init(self, gadgets, heap_min, heap_size, quit_addr, user_callback, userdata):
        self.gadgets = gadgets
        heapaddr = self.qlkit.mem.find_free_space(heap_size, minaddr = heap_min)
        heap = QlMemoryHeap(self.qlkit, heapaddr, heapaddr + heap_size)
        setattr(self.qlkit.os, "heap", heap)
        self.cflow_start, self.cflow_end = self.top_cflow_prepare(
                quit_addr, user_callback, userdata
        )

    def reset_archpc_and_result_callback(self):
        if(self.cflow_start == None):
            print("Environment preparation error")
            return False
        self.qlkit.reg.arch_pc = self.cflow_start
        return True

    def last_code_addr(self):
        return self.cflow_end

    def emulater_gadgets(
            self,
            gadgets, user_callback, userdata,
            libc_addrs = None, quit_addr = None, 
    ):
        stack_address = self.qlkit.loader.stack_address
        if quit_addr == None:
            quit_addr = self.qlkit.os.entry_point

        def emustop(qlkit, *args):
            qlkit.emu_stop()
        self.qlkit.my_hook_code(
                quit_addr, emustop, None
        )
        gadgets = get_util_gadgets(self.qlkit, libc_addrs) + gadgets

        self.gadgets = gadgets
        self.cflow_start, self.cflow_end = self.top_cflow_prepare(
                quit_addr, user_callback, userdata
        )

        print(self.qlkit.mem.show_mapinfo())
        # print("emu_gadgets %s -> %s" % (
        #     hex(self.cflow_start),
        #     hex(self.cflow_end))
        # )
        return self.qlkit.my_emu_start(self.cflow_start, self.cflow_end)

def addr_tuple(**kw):
    new_tuple = namedtuple("addr_tuple", list(kw))
    return new_tuple(**kw)
