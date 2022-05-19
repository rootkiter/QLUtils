#!/bin/python
###############################################
# File Name : Gadget/Arch/ArchGadgetBase.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-11 13:06:05 CST
###############################################

import abc
from typing import Callable
from .. import GadgetBase

class ArchTranslateAbs(abc.ABC):
    @abc.abstractmethod
    def get_return_address(self, qlkit):
        return 0

    @abc.abstractmethod
    def get_args_value(self, qlkit, arg_nr):
        return 0

    @abc.abstractmethod
    def get_return_value(self, qlkit):
        return qlkit.reg.v0

    def get_result_value(self, qlkit):
        return {"ret": self.get_return_value(qlkit)}

    @abc.abstractmethod
    def set_ret_value(self, qlkit, value):
        # qlkit.reg.retreg = value
        pass

    @abc.abstractmethod
    def is_call_inst(self, address, mnemonic, op_str):
        return False

    def ret_to_addr(self, qlkit, addr):
        qlkit.reg.arch_pc = addr

    def get_6_args(self, qlkit):
        resmap = {}
        for i in range(0, 6):
            resmap['arg%d' % i]  = self.get_args_value(qlkit, i)
        return resmap

    def get_regs_value(self, qlkit):
        res = {}
        for name in qlkit.reg.register_mapping:
            val = getattr(qlkit.reg, name)
            res[name] = val
        return res


class ArchGadgetAbs(GadgetBase, abc.ABC):
    def __init__(
            self,
            alias=None, debug = False, mem_write_mon = False,
            print_all_insts = False,
            *arg, **kw
    ):
        super().__init__(alias, *arg, **kw)
        self.debug  = debug
        self.print_all_insts = print_all_insts
        self.mem_write_mon = mem_write_mon
        self._is_running = False
        self.help_bins_addr = (0, 0)

    @abc.abstractmethod
    def env_prepare_assemble(self, old_sp_addr):
        return []

    @abc.abstractmethod
    def env_recover_assemble(self):
        return []

    @abc.abstractmethod
    def call_sub_func_assemble(self, *args):
        return [], None

    @abc.abstractmethod
    def nop_code_for_hook(self):
        return []

    @abc.abstractmethod
    def exit_address_assemble(self, quitaddr):
        return []

    @abc.abstractmethod
    def result_dump(self, qlkit):
        return {}

    def addr_belongs_help_bins(self, addr):
        start, end = self.help_bins_addr
        return addr>=start and addr <= end

    def belongs_to_lv1_code_block(self, qlkit, curr_inst):
        return False

    def asm_before_hook(self, old_sp_addr, *args):
        env_pre_asm       = self.env_prepare_assemble(old_sp_addr)
        call_asm, brkaddr = self.call_sub_func_assemble( *args )
        pre_asms = env_pre_asm + call_asm
        return pre_asms, brkaddr

    def dbg_print_flag(self):
        if self.is_running() and self.debug:
            return True
        return False

    def need_trace_inst(self):
        if self.debug or self.mem_write_mon:
            return True
        return False

    def install_hook_callback(
        self, qlkit,
        reg_args, quitaddr, callback, userdata
    ):
        sp_pointer_now = qlkit.reg.arch_sp
        pre_asms, brkaddr = self.asm_before_hook(
                sp_pointer_now, *reg_args
        )

        tail_asms = self.asm_after_hook(quitaddr)
        if brkaddr != None:
            tail_asms = self.nop_code_for_hook() + tail_asms

        stop_asms = self.nop_code_for_hook()

        pre_bins, num  = qlkit.assembler.asm(" ; ".join(pre_asms))
        tail_bins, num = qlkit.assembler.asm(" ; ".join(tail_asms))
        dbg_stop_bins, num = qlkit.assembler.asm(" : ".join(stop_asms))
        total_bins = pre_bins + tail_bins + dbg_stop_bins
        total_bin_size = len(total_bins)

        start_addr     = qlkit.mem_align_alloc(total_bin_size+0x100)
        code_end_addr  = start_addr    + len(pre_bins)
        stop_addr      = code_end_addr + len(tail_bins)

        def hard_jmp_pc(qlkit, addr, toaddr):
            qlkit.reg.arch_pc = toaddr

        if brkaddr != None:
            qlkit.my_hook_code(brkaddr, hard_jmp_pc, (code_end_addr))

        # addr-queue
        # start_addr - pre_start - code_start - code_end - tail_end - quit_addr
        #                  | pre_bins  |            | tail_bins |
        qlkit.mem.write(start_addr, bytes(total_bins))
        total_end_addr = start_addr + len(total_bins)
        self.help_bins_addr = (start_addr, total_end_addr)

        self.other_hook_need(
                qlkit, code_end_addr, stop_addr,
                (self, callback, userdata)
        )

        # self.hook_trigger(qlkit, start_addr)
        return start_addr

    def hook_trigger(self, qlkit, addr):
        def trigger_print(qlkit, address, *args):
            print("trigger -> ", hex(address))
        qlkit.my_hook_code(addr, trigger_print, None)

    def other_hook_need(self, qlkit, code_end, stop, argsinside):
        if hasattr(self, "start"):
            self.hook_run_before(qlkit, self.start, argsinside)
        self.hook_run_finish(qlkit, code_end  , argsinside)
        if self.need_trace_inst():
            self.code_execute_monitor(qlkit, argsinside)
        if self.mem_write_mon:
            self.monitor_memory_write_at_codes(qlkit, argsinside)

    def monitor_memory_write_at_codes(self, qlkit, argsinside):
        def on_mem_write(qlkit, access, addr, size, value):
            instaddr = qlkit.reg.arch_pc
            if not self.belongs_to_lv1_code_block(qlkit, None):
                return
            resmap = {
                    'pc': qlkit.reg.arch_pc,
                    'addr': addr,
                    'size': size,
                    'value': value,
            }
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)

            gdt, gdt_callback, gdt_data = argsinside
            label_gdt = GadgetBase("%s_mem_write" % (gdt.Alias), 0)
            if gdt_callback != None:
                gdt_callback(qlkit, label_gdt, result, gdt_data)
        qlkit.hook_mem_write(on_mem_write)

    def code_execute_monitor(self, qlkit, argsinside):
        def on_every_function_inst(inst):
            if self.dbg_print_flag():
                hexstr = "".join(map(lambda x: "%02x" % x, inst.bytes))
                guess_reg_use_list =  \
                    str(inst.op_str).replace(",", " ")\
                    .replace("[", " ").replace("]", " ")\
                    .replace("{", " ").replace("}", " ")\
                    .replace("(", " ").replace(")", " ")\
                    .replace("$", " ")\
                    .split()
                resmap = {}
                for guess_reg in guess_reg_use_list:
                    if guess_reg in qlkit.reg.register_mapping:
                        value = getattr(qlkit.reg, guess_reg)
                        resmap[guess_reg] = hex(value)
                print("%-10s %-20s %-40s %s" % (
                    hex(inst.address), hexstr,
                    inst.mnemonic +" "+ inst.op_str, str(resmap)[:150]
                ))

        def on_every_inst(qlkit, addr, size):
            bin_code_buf = qlkit.mem.read(addr, size)

            insts = qlkit.disassembler.disasm(bin_code_buf, addr)
            for inst in insts:
                # belongs_to_lv1_code_block() must be checked before self.print_all_insts
                if not self.belongs_to_lv1_code_block(qlkit, inst) and not self.print_all_insts:
                    continue
                on_every_function_inst(inst)
        if hasattr(self, "start"):
            qlkit.hook_code(on_every_inst, None, self.start, 0)

    def hook_run_finish(self, qlkit, fin_addr, argsinside):
        def finish_gadget(qlkit, address, each_gdt_data):
            gdt, gdt_callback, gdt_data = each_gdt_data
            resmap = gdt.result_dump(qlkit)
            resmap['ret'] = self.get_return_value(qlkit)
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            if gdt_callback != None:
                label_gdt = GadgetBase("%s_done" % (gdt.Alias), 0)
                gdt_callback(qlkit, gdt, result, gdt_data)
                gdt_callback(qlkit, label_gdt, result, gdt_data)
        qlkit.my_hook_code(
                fin_addr, finish_gadget, argsinside
        )

    def hook_run_before(self, qlkit, start_addr, userdata):
        def hook_before_execute(qlkit, address, argsinside):
            gdt, gdt_callback, gdt_data = argsinside
            label_gdt = GadgetBase("%s_before" % (gdt.Alias), 0)
            if gdt_callback != None:
                gdt_callback(qlkit, label_gdt, None, gdt_data)
        qlkit.my_hook_code(
                start_addr, hook_before_execute,
                userdata
        )


    def asm_after_hook(self, quitaddr):
        recover_asm = self.env_recover_assemble()
        exit_asm    = self.exit_address_assemble(quitaddr)
        tail_asms   =  recover_asm + exit_asm
        return tail_asms

class StackBalance(ArchGadgetAbs, ArchTranslateAbs):
    def result_dump(self, qlkit):
        return self.get_regs_value(qlkit)

    def nop_code_for_hook(self):
        return ['nop']

class _share_belongs_lv1_check_method:
    def belongs_to_lv1_code_block(self, qlkit, inst):
        address = qlkit.reg.arch_pc
        mnemonic = "nop"
        op_str   = ""
        if inst != None:
            address = inst.address
            mnemonic = inst.mnemonic
            op_str   = inst.op_str

        if not self.is_running():
            return False
        if self.addr_belongs_help_bins(address):
            return False

        if self.call_address == 0:
            if self.is_call_inst(address, mnemonic, op_str):
                self.call_address = address
            self.last_address = address
            return True
        else:
            if address >= self.last_address and address <= self.last_address + 15:
                self.last_address = address
                self.count_number += 1
                if self.count_number >= 2:
                    self.call_address = 0
                    self.ret_address  = 0
                    self.count_number = 0
                return True
            if self.ret_address == 0:
                # the first inst of sub-function
                if address == self.call_address:
                    return True
                self.ret_address = self.get_return_address(qlkit)
                if address < self.ret_address and address + 15 >= self.ret_address:
                    # Delay inst need check here
                    return True
            else:
                # the stack_pointer is match .. check ret_address next
                if address == self.ret_address:
                    self.call_address = 0
                    self.ret_address  = 0
                    self.count_number = 0
                    if self.is_call_inst(address, mnemonic, op_str):
                        # The status of two consecutive calls
                        self.call_address = address
                    return True
        return False



class CallFunctionAbs(StackBalance, _share_belongs_lv1_check_method):
    def __init__(self, alias, addr, argnum, **kw):
        new_ali = "%s" % (alias)
        super().__init__(addr, alias = new_ali, argnum = argnum, **kw)
        self.start          = addr

        # trace sub-function
        self.call_address   = 0
        self.ret_address    = 0

        # when sub-function trace don't expected. reset the trace flag
        #  This part mainly deals with HookFunction gadget.
        self.last_address   = addr
        self.count_number   = 0

class RunCodesAbs(StackBalance, _share_belongs_lv1_check_method):
    def __init__(self, start, end, argnum=0, **kw):
        super().__init__(argnum=argnum, **kw)
        self.start = start
        self.end   = end


class MonitorGadgetAbs(GadgetBase, abc.ABC):
    def __init__(self, alias, addr_be_monitor, argnum=0, **kw):
        super().__init__(alias=alias, argnum=argnum, **kw)
        self.addr = addr_be_monitor

    def ql_install(
        self, qlkit, callback, userdata
    ):
        def mon_cbk(qlkit, address, argsinside):
            # callback, userdata = argsinside
            resmap = self.result_dump(qlkit)
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            if callback != None:
                callback(qlkit, self, result, userdata)

        qlkit.my_hook_code(
            self.addr, mon_cbk, None, False
        )
    pass

class HookFunctionBaseAbs(GadgetBase, ArchTranslateAbs):
    def __init__(self, alias, funccbk, argnum=0, no_cbk=True, **kw):
        super().__init__(
            alias=alias, argnum=argnum, no_cbk=no_cbk, **kw
        )
        self.my_func  = funccbk

    def callback_process(self, qlkit, addr, q_c_u):
        qlkit, callback, userdata = q_c_u
        def callback_trigger(qlkit, alias, gadget, cbk, resmap, userdata):
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)

            # Alias control for Hook then recovery it
            alias_bak = self._alias
            gadget._alias = alias
            cbk(qlkit, gadget, result, userdata)
            gadget._alias = alias_bak

        arglist = []
        resmap = {}
        for nr in range(0, self.arg_need()):
            argvalue = self.get_args_value(qlkit, nr)
            arglist.append(argvalue)
            resmap["arg%d" % nr] = argvalue
        retaddr = self.get_return_address(qlkit)
        resmap['retaddr']  = retaddr

        callback_trigger(
               qlkit, "%s_before" % self.Alias,
               self, callback, resmap, userdata
        )

        # process the hook
        retvalue = self.my_func(qlkit, *arglist)
        self.set_ret_value(qlkit, retvalue)
        self.ret_to_addr(qlkit, retaddr)

        resmap['ret']      = retvalue
        callback_trigger(
               qlkit, "%s_done" % self.Alias,
               self, callback, resmap, userdata
        )


class HookFunctionAbs(HookFunctionBaseAbs):
    def __init__(
            self, alias, func_addr, funccbk, argnum=0, no_cbk=True, **kw
    ):
        super().__init__(
            alias=alias, funccbk=funccbk, argnum=argnum, no_cbk=no_cbk, **kw
        )
        self.funcaddr = func_addr

    def ql_install(self, qlkit, callback, userdata):
        q_c_u = (qlkit, callback, userdata)
        qlkit.my_hook_code(
            self.funcaddr, self.callback_process, q_c_u, False
        )


# [!] need recode DynHookAbs By HookFunctionBaseAbs
class DynHookAbs(GadgetBase, ArchTranslateAbs):
    def __init__(self, funcname, new_func, argnum, no_cbk=True, **kw):
        if 'alias' not in kw:
            kw['alias']="dyn_%s" % funcname
        super().__init__(argnum=argnum, no_cbk=no_cbk, **kw)
        self.funcname = funcname
        self.new_func = new_func

    def ql_install(self, qlkit, callback, userdata ):
        def dyn_func_cbk(qlkit, *args):
            arglist = []
            resmap = {}
            for nr in range(0, self.arg_need()):
                argvalue = self.get_args_value(qlkit, nr)
                arglist.append(argvalue)
                resmap["arg%d" % nr] = argvalue

            ret = self.new_func(qlkit, *arglist)
            resmap['ret'] = ret
            if isinstance(ret, int):
                self.set_ret_value(qlkit, ret)
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            callback(qlkit, self, result, userdata)
        qlkit.hook_dyn_function(
                self.funcname, dyn_func_cbk
        )

from qiling.const import QL_INTERCEPT
class SyscallPatchAbs(GadgetBase, ArchTranslateAbs):
    def __init__(self, sysname, sys_method, argnum=0, **kw):
        self.sysname = sysname
        self.sys_method = sys_method
        super().__init__(alias=sysname, argnum=argnum, **kw)

    def ql_install(self, qlkit, callback, userdata ):
        def callback_trigger(qlkit, alias, gadget, cbk, resmap, userdata):
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)

            # Alias control for Hook then recovery it
            alias_bak = self._alias
            gadget._alias = alias
            ret = cbk(qlkit, gadget, result, userdata)
            gadget._alias = alias_bak
            return ret

        def cbk(qlkit, *args):
            resmap = {}
            funcname, real_args, ret = self.sys_method(qlkit, *args)
            for nr in range(0, len(real_args)):
                resmap['arg%d' % nr] = real_args[nr]

            resmap['funcname'] = funcname
            resmap['ret'] = ret

            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            cbk_ret = callback_trigger(
                    qlkit, "sys_%s" % funcname,
                    self, callback, resmap, userdata
            )
            if isinstance(cbk_ret, int):
                ret = cbk_ret
            return ret

        def sys_method_syscall_6_arg(qlkit, arg1, arg2, arg3, arg4, arg5, arg6, *args):
            return cbk(qlkit, arg1, arg2, arg3, arg4, arg5, arg6)

        def sys_method_syscall_5_arg(qlkit, arg1, arg2, arg3, arg4, arg5, *args):
            return cbk(qlkit, arg1, arg2, arg3, arg4, arg5)

        def sys_method_syscall_4_arg(qlkit, arg1, arg2, arg3, arg4, *args):
            return cbk(qlkit, arg1, arg2, arg3, arg4)

        def sys_method_syscall_3_arg(qlkit, arg1, arg2, arg3, *args):
            return cbk(qlkit, arg1, arg2, arg3)

        def sys_method_syscall_2_arg(qlkit, arg1, arg2, *args):
            return cbk(qlkit, arg1, arg2)

        def sys_method_syscall_1_arg(qlkit, arg1, *args):
            return cbk(qlkit, arg1)

        callback_map = {
                1 : sys_method_syscall_1_arg,
                2 : sys_method_syscall_2_arg,
                3 : sys_method_syscall_3_arg,
                4 : sys_method_syscall_4_arg,
                5 : sys_method_syscall_5_arg,
                6 : sys_method_syscall_6_arg,
        }
        callback_inst = callback_map[self.arg_need()]
        qlkit.set_syscall(self.sysname, callback_inst, QL_INTERCEPT.CALL)

class MonitorCodeAddressAbs(MonitorGadgetAbs, ArchTranslateAbs):
    def result_dump(self, qlkit):
        resmap = {}
        resmap.update(self.get_regs_value(qlkit))
        return resmap

class MonitorGadgetFuncExitAbs(MonitorGadgetAbs, ArchTranslateAbs):
    def result_dump(self, qlkit):
        res = {}
        res.update(self.get_regs_value(qlkit))
        res.update(self.get_result_value(qlkit))
        return res

    def ql_install(self, qlkit, callback, userdata):
        def mon_func_quit(qlkit, address, entryargs):
            resmap = self.result_dump(qlkit)
            resmap.update(entryargs)
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            if callback != None:
                callback(qlkit, self, result, userdata)

        def mon_func_entry(qlkit, address, argsinside):
            # get return address when func entry
            quit_address = self.get_return_address(qlkit)
            entryargs = self.get_6_args(qlkit)
            qlkit.my_hook_code(
                quit_address, mon_func_quit, entryargs
            )
        qlkit.my_hook_code(
            self.addr, mon_func_entry, None, False
        )

