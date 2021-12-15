#!/bin/python
###############################################
# File Name : ArchGadget/Arch/MipsGadget.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-11 12:37:06 CST
###############################################

from .ArchGadgetBase import StackBalance, MonitorGadgetAbs, ArchTranslateAbs
from .ArchGadgetBase import MonitorCodeAddressAbs
from .ArchGadgetBase import MonitorGadgetFuncExitAbs
from .ArchGadgetBase import CallFunctionAbs, RunCodesAbs, HookFunctionAbs, DynHookAbs, SyscallPatchAbs

class MIPS_ArchTranslate(ArchTranslateAbs):
    def get_return_address(self, qlkit):
        return  qlkit.reg.ra

    def get_return_value(self, qlkit):
        return qlkit.reg.v0

    def get_args_value(self, qlkit, argnr):
        if argnr < 4:
            return getattr(qlkit.reg, "a%d" % argnr)
        elif argnr == 4:
            return qlkit.mem.read_ptr(qlkit.reg.arch_sp+0x10, 4)
        elif argnr == 5:
            return qlkit.mem.read_ptr(qlkit.reg.arch_sp+0x14, 4)

    def set_ret_value(self, qlkit, retvalue):
        qlkit.reg.v0 = retvalue

    def is_call_inst(self, address, mnemonic, op_str):
        return mnemonic.lower() in ('jalr', 'jr') and op_str != "$ra"

class Mips32StackBalance(StackBalance, MIPS_ArchTranslate):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._regs_bak = [
            'a0', 'a1', 'a2', 'a3', 'v0', 'v1', 'ra', 't9', 'fp'
        ]
        self.spsize    = 0
        self._old_sp = None

    def env_prepare_assemble(self, old_sp):
        # 3 times space, one for more args, one for buffer protect
        self._old_sp = old_sp
        self._need_bytes = len(self._regs_bak)*4
        self.spsize  = self._need_bytes*3
        asm_list = ['addiu $sp, -%s' % hex(self.spsize)]
        for regoff in range(0, len(self._regs_bak)):
            reg = self._regs_bak[regoff]
            asm_list.append(
                'sw    $%s, %4s($sp)' % (reg, hex(self._need_bytes+regoff*4))
            )
        return asm_list + ['nop']

    def env_recover_assemble(self):
        asm_list = [
            'li $sp, %s' % (hex(self._old_sp)),
            'addiu $sp, -%s' % hex(self.spsize)
        ]
        for regoff in range(0, len(self._regs_bak)):
            reg = self._regs_bak[regoff]
            asm_list.append(
                'lw    $%s, %4s($sp)' % (reg, hex(self._need_bytes+regoff*4))
            )
        asm_list .append(
            'addiu $sp, %s' % hex(self.spsize)
        )
        return asm_list + ['nop']

    def exit_address_assemble(self, quitaddr):
        asm_list = [
            'li      $ra,  %s' % hex(quitaddr),
            'jr      $ra',
            "nop"
        ]
        return asm_list

class Mips4ArgBase(Mips32StackBalance):
    def __init__(self, funcaddr, **kw):
        super().__init__(**kw)
        self.funcaddr = funcaddr
        self.argnum   = 4
        if 'argnum' in kw:
            self.argnum = kw['argnum']
        self._ret_regs = [
            'a0', 'a1', 'a2', 'a3', 'v0', 'v1', 't9'
        ]

    def call_sub_func_assemble(self, a0=0, a1=0, a2=0, a3=0):
        asm_list = [
            "li    $a3, %s" % hex(a3)  ,
            "li    $a2, %s" % hex(a2)  ,
            "li    $a1, %s" % hex(a1)  ,
            "li    $a0, %s" % hex(a0)  ,
            "li    $t9, %s" % hex(self.funcaddr),
            "jalr  $t9"            ,
            "nop"
        ]
        return asm_list, None

class MONITOR_ADDRESS(MonitorCodeAddressAbs, MIPS_ArchTranslate):
    pass

class MONITOR_FUNC_EXIT(MonitorGadgetFuncExitAbs, MIPS_ArchTranslate):
    pass

class CALL_FUNC(CallFunctionAbs, Mips4ArgBase):
    pass

class HookFunction(HookFunctionAbs, MIPS_ArchTranslate):
    pass

class DynHookFunction(DynHookAbs, MIPS_ArchTranslate):
    # md5 : 8790940e6aae334360512a540f9a8eee
    def ql_install(self, qlkit, callback, userdata ):
        def dyn_func_cbk(qlkit, *args):
            arglist = []
            resmap = {}
            for nr in range(0, self.arg_need()):
                argvalue = self.get_args_value(qlkit, nr)
                arglist.append(argvalue)
                resmap["arg%d" % nr] = argvalue

            retaddr = self.get_return_address(qlkit)
            ret = self.new_func(qlkit, *arglist)
            resmap['ret'] = ret
            if isinstance(ret, int):
                self.set_ret_value(qlkit, ret)
            from collections import namedtuple
            curr_result = namedtuple("current_result", list(resmap))
            result = curr_result(**resmap)
            callback(qlkit, self, result, userdata)
            self.ret_to_addr(qlkit, retaddr)
        func_addr = qlkit.find_symbols_name(self.funcname)
        if func_addr != None:
            qlkit.my_hook_code(
                    func_addr, dyn_func_cbk, userdata, trigger_once=False
            )

class RUNCODES(RunCodesAbs, Mips32StackBalance):
    def call_sub_func_assemble(self, *args):
        asm_list = [
            'li      $t9,  %s' % hex(self.start),
            'jr      $t9',
            'nop'
        ]
        return asm_list, self.end

class PATCH_SYSCALL(SyscallPatchAbs, MIPS_ArchTranslate):
    pass
