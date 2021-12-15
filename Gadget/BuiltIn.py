#!/bin/python
###############################################
# File Name : BuiltInGadget.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-11 11:32:40 CST
###############################################

import abc
# from . import GadgetBase
from typing import Callable
from collections import namedtuple

class GadgetBase(object):
    def __init__(self, alias, argnum, no_cbk=False):
        self._alias  = alias
        self._argnum = argnum
        self._no_cbk = no_cbk
        self._is_running = False

    @property
    def Alias(self):
        if self._alias == None:
            return self.Mnem
        return self._alias

    @property
    def Mnem(self):
        clzname = self.__class__.__name__
        return clzname

    @property
    def need_callback(self):
        return not self._no_cbk

    def start_trigger(self):
        self._is_running = True

    def stop_trigger(self):
        self._is_running = False

    def is_running(self):
        return self._is_running

    def arg_need(self):
        return self._argnum

    def __str__(self):
        return "%s %d" % (self.Mnem(), self.arg_need())

class BuiltInGadgetAbs(GadgetBase, abc.ABC):
    def __init__(self, alias=None, argnum = 0):
        super().__init__(alias, argnum)

    def runit(self, qlkit, rcbnarchive):
        return self.result_map_dump(qlkit, rcbnarchive)

    @abc.abstractmethod
    def result_map_dump(self, qlkit, rcbnarchive):
        return {}

class MonitorMemAbs(GadgetBase, abc.ABC):
    def __init__(self, alias=None, argnum=0, **kw):
        super().__init__(alias=alias, argnum=argnum, **kw)

    def _hook_install(self, qlkit, addr, size, rcbnarchive, callback, userdata):
        def mem_cbk(qlkit, access, address, size, value):
            if callback != None:
                pcaddr = qlkit.reg.arch_pc
                secname = None
                if qlkit.addr_belongs_binary(address):
                    secname = qlkit.addr_belongs_section_name(address)
                resmap = {
                        "pc"   : qlkit.reg.arch_pc,
                        'addr' : address,
                        'size' : size,
                        'val'  : value,
                        'sec'  : secname
                }
                current_result = namedtuple("current_result", list(resmap))
                result = current_result(**resmap)
                callback(qlkit, self, result, userdata)
        hookhandle = self.hook_handle(qlkit)
        if addr == None:
            hookhandle(mem_cbk)
        else:
            hookhandle(mem_cbk, begin = addr, end = addr+size)

    @abc.abstractmethod
    def hook_install(self, qlkit, rcbnarchive, callback, userdata):
        pass

class Monitor_handleAbs(abc.ABC):
    @abc.abstractmethod
    def hook_handle(self, qlkit):
        return qlkit.hook_mem_read

class MonitorReadHandle(Monitor_handleAbs):
    def hook_handle(self, qlkit):
        return qlkit.hook_mem_read

class MonitorWriteHandle(Monitor_handleAbs):
    def hook_handle(self, qlkit):
        return qlkit.hook_mem_write

class MonitorAddrRWAbs(MonitorMemAbs, Monitor_handleAbs):
    def __init__(self, archivekey, monsize=1, alias=None, argnum=0, **kw):
        super().__init__(alias=alias, argnum=argnum, **kw)
        self.monitorkey = archivekey
        self.monsize    = monsize

    def hook_install(self, qlkit, rcbnarchive, callback, userdata):
        memaddr = rcbnarchive.get_archive(self.monitorkey)
        self._hook_install(
                qlkit, memaddr, self.monsize, rcbnarchive,
                callback, userdata
        )

class Monitor_MEM_RW_Abs(MonitorMemAbs, Monitor_handleAbs):
    def __init__(self, alias = None, argnum = 0, **kw):
        super().__init__(alias=alias, argnum=argnum, **kw)

    def hook_install(self, qlkit, rcbnarchive, callback, userdata):
        self._hook_install(
                qlkit, None, 0, rcbnarchive,
                callback, userdata
        )

class MONITOR_ADDR_READ(MonitorAddrRWAbs, MonitorReadHandle):
    pass

class MONITOR_ADDR_WRITE(MonitorAddrRWAbs, MonitorWriteHandle):
    pass

class MONITOR_MEM_READ(Monitor_MEM_RW_Abs, MonitorReadHandle):
    pass

class MONITOR_MEM_WRITE(Monitor_MEM_RW_Abs, MonitorWriteHandle):
    pass

class PUSH_NUM(BuiltInGadgetAbs):
    def __init__(self, number, **kw):
        super().__init__(**kw)
        self.number = number

    def result_map_dump(self, qlkit, rcbnarchive):
        rcbnarchive.push_num(self.number)
        return {self.Mnem: self.number}

class POP_NUM(BuiltInGadgetAbs):
    def __init__(self, **kw):
        super().__init__(**kw)

    def result_map_dump(self, qlkit, rcbnarchive):
        number = rcbnarchive.pop_num()
        return {self.Mnem: number}

class PUSH_POINTER(BuiltInGadgetAbs):
    def __init__(self, archivekey, **kw):
        super().__init__(**kw)
        self.archivekey = archivekey

    def result_map_dump(self, qlkit, rcbnarchive):
        number = rcbnarchive.get_archive(self.archivekey)
        rcbnarchive.push_num(number)
        return {'PUSH': "%s # %s" % (self.archivekey, hex(number))}

class SET_PC(BuiltInGadgetAbs):
    def __init__(self, quit_pc, **kw):
        super().__init__(**kw)
        self.quit_pc = quit_pc

    def result_map_dump(self, qlkit, rcbnarchive):
        qlkit.reg.arch_pc = self.quit_pc
        return {self.Mnem: "%s" % (hex(self.quit_pc))}

class REGARCHIVE(BuiltInGadgetAbs):
    def __init__(self, regname, archivekey, **kw):
        super().__init__(**kw)
        self.regname = regname
        self.archivekey = archivekey

    def result_map_dump(self, qlkit, rcbnarchive):
        value = getattr(rcbnarchive.lastres, self.regname)
        rcbnarchive.archive(self.archivekey, value)
        return {self.archivekey: value}

class MEMPATCH(BuiltInGadgetAbs):
    def __init__(self, archivekey, bts, **kw):
        super().__init__(**kw)
        self.archivekey = archivekey
        self.bts        = bytes(bts)

    def result_map_dump(self, qlkit, rcbnarchive):
        addr = rcbnarchive.get_archive(self.archivekey)
        qlkit.mem.write(addr, self.bts)
        return {self.archivekey: "%s: %s" % (hex(addr), str(self.bts))}

class GOT_POINTER_INIT(BuiltInGadgetAbs):
    def __init__(self, got_name, **kw):
        alias = "got_patch_%s" % got_name
        super().__init__(alias=alias, **kw)
        self.got_name = got_name

    def result_map_dump(self, qlkit, rcbnarchive):
        tmpaddr = qlkit.mem_heap_alloc(qlkit.archbytes)
        qlkit.set_got_value(self.got_name, tmpaddr)
        return {"got_value_init": tmpaddr}



class STACKALLOC(BuiltInGadgetAbs):
    def __init__(self, name, size, **kw):
        super().__init__(**kw)
        self.name = name
        self.size = size
        self.realsize = 0
        self.old_sp   = 0
        self.new_sp   = 0

    def result_map_dump(self, qlkit, rcbnarchive):
        if self.size == None or self.size <= 0:
            return {'Exception': "AllocSize(%s) <= 0" % (str(self.size))}
        self.old_sp = qlkit.reg.arch_sp
        u64size = int(self.size / 8) # + ((self.size%4 == 0) ? 0:1)
        if self.size%8 != 0:
            u64size += 1
        realbytes = u64size * 8
        self.realsize = realbytes
        self.new_sp = self.old_sp-self.realsize
        qlkit.reg.arch_sp = self.new_sp
        rcbnarchive.archive(self.name, self.new_sp)
        return {"addr": self.new_sp, "size": realbytes, "old_sp": self.old_sp}

class EXIT(SET_PC):
    def result_map_dump(self, qlkit, rcbnarchive):
        super().result_map_dump(qlkit, rcbnarchive)
        return {self.Mnem: "Exit"}

class LABEL(BuiltInGadgetAbs):
    def __init__(self, alias, **kw):
        super().__init__(alias=alias, **kw)

    def result_map_dump(self, qlkit, rcbnarchive):
        return {self.Mnem: self._alias}

if __name__=='__main__':
    inst = PUSH_NUM(20, alias = "TEST")
    print(str(inst))

    inst = CALL_FUNC("calloc", 0x42424242, 2)
    print(str(inst))
