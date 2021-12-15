#!/bin/python
###############################################
# File Name : QLUtils/Gadget/Arch/X686Gadgets.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-26 10:48:02 CST
###############################################

from .ArchGadgetBase import StackBalance, MonitorGadgetAbs, ArchTranslateAbs
from .ArchGadgetBase import MonitorCodeAddressAbs
from .ArchGadgetBase import MonitorGadgetFuncExitAbs
from .ArchGadgetBase import CallFunctionAbs, RunCodesAbs
from .ArchGadgetBase import CallFunctionAbs, RunCodesAbs, HookFunctionAbs, DynHookAbs, SyscallPatchAbs


class X686_ArchTranslate(ArchTranslateAbs):
    def get_return_address(self, qlkit):
        retaddr = qlkit.stack_read(0)
        return retaddr

    def get_args_value(self, qlkit, argnr):
        return qlkit.stack_read(4*(argnr+1))

    def get_return_value(self, qlkit):
        return qlkit.reg.eax

    def set_ret_value(self, qlkit, retvalue):
        qlkit.reg.eax = retvalue

    def ret_to_addr(self, qlkit, addr):
        stackaddr = qlkit.stack_pop()
        qlkit.reg.arch_pc = addr

    def is_call_inst(self, address, mnemonic, op_str):
        return mnemonic.lower() in ("call")

class X686StackBalance(StackBalance, X686_ArchTranslate):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.spsize = 0
        self._old_sp = None

    def env_prepare_assemble(self, old_sp):
        self._old_sp = old_sp
        self.spsize  = 7*4
        asm_list = [
                'push ebp',
                'push eax',
                'push ebx',
                'push ecx',
                'push edx',
                'push esi',
                'push edi',
        ]
        return asm_list

    def env_recover_assemble(self):
        spaddr = self._old_sp - self.spsize
        asm_list = [
                'push %s' % hex(spaddr),
                'pop  esp',  # stack balance

                'pop  edi',  # recover regs
                'pop  esi',
                'pop  edx',
                'pop  ecx',
                'pop  ebx',
                'pop  eax',
                'pop  ebp',
        ]
        return asm_list

    def exit_address_assemble(self, quitaddr):
        asm_list = [
                'push eax',
                'mov  eax, %s' % hex(quitaddr),
                'xchg eax, [esp]',
                'ret'
        ]
        return asm_list

class X686_4ArgBase(X686StackBalance):
    def __init__(self, funcaddr, **kw):
        super().__init__(**kw)
        self.funcaddr = funcaddr
        self.argnum   = 4
        if 'argnum' in kw:
            self.argnum = kw['argnum']

    def call_sub_func_assemble(self, arg0 = 0, arg1=0, arg2 = 0, arg3=0):
        asm_list = [
                'push %s' % (hex(arg3)),
                'push %s' % (hex(arg2)),
                'push %s' % (hex(arg1)),
                'push %s' % (hex(arg0)),

                'push %s' % (hex(self.funcaddr)),
                'pop  edx',
                'call edx', # % call self.funcaddr,
                'nop'
        ]
        return asm_list, None

class MONITOR_ADDRESS(MonitorCodeAddressAbs, X686_ArchTranslate):
    pass

class MONITOR_FUNC_EXIT(MonitorGadgetFuncExitAbs, X686_ArchTranslate):
    pass

class CALL_FUNC(CallFunctionAbs, X686_4ArgBase):
    pass


class HookFunction(HookFunctionAbs, X686_ArchTranslate):
    pass

class DynHookFunction(DynHookAbs, X686_ArchTranslate):
    pass

class RUNCODES(RunCodesAbs, X686StackBalance):
    def call_sub_func_assemble(self, *args):
        asm_list = [
                'push %s' % (hex(self.start)),
                'pop  edx',
                'call edx', # % call self.funcaddr,
                'nop'
        ]
        return asm_list, self.end

class PATCH_SYSCALL(SyscallPatchAbs, X686_ArchTranslate):
    pass
