#!/bin/python
###############################################
# File Name : QLUtils/Gadget/Arch/X8664Gadgets.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-28 16:51:24 CST
###############################################

from .ArchGadgetBase import StackBalance, MonitorGadgetAbs, ArchTranslateAbs
from .ArchGadgetBase import MonitorCodeAddressAbs
from .ArchGadgetBase import MonitorGadgetFuncExitAbs
from .ArchGadgetBase import CallFunctionAbs, RunCodesAbs, HookFunctionAbs, DynHookAbs, SyscallPatchAbs

class X8664_ArchTranslate(ArchTranslateAbs):
    def get_return_address(self, qlkit):
        return qlkit.stack_read(0)

    def get_args_value(self, qlkit, argnr):
        if argnr == 0:
            return qlkit.reg.rdi
        elif argnr == 1:
            return qlkit.reg.rsi
        elif argnr == 2:
            return qlkit.reg.rdx
        elif argnr == 3:
            return qlkit.reg.rcx
        elif argnr == 4:
            return qlkit.reg.r8d
        return None

    def set_ret_value(self, qlkit, retvalue):
        qlkit.reg.rax = retvalue

    def ret_to_addr(self, qlkit, addr):
        stackaddr = qlkit.stack_pop()
        qlkit.reg.arch_pc = addr

    def get_return_value(self, qlkit):
        return qlkit.reg.rax

    def is_call_inst(self, address, mnemonic, op_str):
        # 8db6a2be934395d6e5d55a665eedd3b9_0x408a90 is a jmp check case
        if not hasattr(self, 'jmp_check_address'):
            setattr(self, "jmp_check_address", None)
        if self.jmp_check_address == None:
            if mnemonic.lower() in ('jmp'):
                self.jmp_check_address = address
                return True
            return mnemonic.lower() in ("call")
        else:
            if address > self.jmp_check_address + 0x2000 \
                    or address + 0x2000 < self.jmp_check_address:
                return False
            return True

class X8664_StackBalance(StackBalance, X8664_ArchTranslate):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.spsize = 0
        self._old_sp = None

    def env_prepare_assemble(self, old_sp):
        self._old_sp = old_sp
        self.spsize  = 7*8
        asm_list = [
                'push rbp',
                'push rax',
                'push rbx',
                'push rcx',
                'push rdx',
                'push rsi',
                'push rdi',
        ]
        return asm_list

    def env_recover_assemble(self):
        spaddr = self._old_sp - self.spsize
        asm_list = [
                'mov rsp, %s' % hex(spaddr),
                # 'pop  rsp',  # stack balance

                'pop rdi',  # recover regs
                'pop rsi',
                'pop rdx',
                'pop rcx',
                'pop rbx',
                'pop rax',
                'pop rbp',
        ]
        return asm_list

    def exit_address_assemble(self, quitaddr):
        asm_list = [
                'push rax',
                'mov  rax, %s' % hex(quitaddr),
                'xchg rax, [rsp]',
                'ret'
        ]
        return asm_list

class X8664_2ArgBase(X8664_StackBalance):
    def __init__(self, funcaddr, **kw):
        super().__init__(**kw)
        self.funcaddr = funcaddr
        self.argnum   = 5
        if 'argnum' in kw:
            self.argnum = kw['argnum']

    def call_sub_func_assemble( self,
            arg0 = 0, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0,
    *args):
        asm_list = [
                'mov  rdi, %s' % (hex(arg0)),
                'mov  rsi, %s' % (hex(arg1)),
                'mov  rdx, %s' % (hex(arg2)),
                'mov  rcx, %s' % (hex(arg3)),
                'mov  r8d, %s' % (hex(arg4)),

                'push %s' % (hex(self.funcaddr)),
                'pop  rdx',
                'call rdx', # % call self.funcaddr,
                'nop'
        ]
        return asm_list, None

class CALL_FUNC(CallFunctionAbs, X8664_2ArgBase):
    pass

class MONITOR_FUNC_EXIT(MonitorGadgetFuncExitAbs, X8664_ArchTranslate):
    pass

class MONITOR_ADDRESS(MonitorCodeAddressAbs, X8664_ArchTranslate):
    pass

class HookFunction(HookFunctionAbs, X8664_ArchTranslate):
    pass

class DynHookFunction(DynHookAbs, X8664_ArchTranslate):
    pass

class RUNCODES(RunCodesAbs, X8664_StackBalance):
    def call_sub_func_assemble(self, *args):
        asm_list = [
                'push %s' % (hex(self.start)),
                'pop  rdx',
                'call rdx', # % call self.funcaddr,
                'nop'
        ]
        return asm_list, self.end

class PATCH_SYSCALL(SyscallPatchAbs, X8664_ArchTranslate):
    pass
