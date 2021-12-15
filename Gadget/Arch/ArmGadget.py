#!/bin/python
###############################################
# File Name : Gadget/Arch/ArmGadget.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-19 18:29:52 CST
###############################################

from .ArchGadgetBase import StackBalance, MonitorGadgetAbs, ArchTranslateAbs
from .ArchGadgetBase import MonitorCodeAddressAbs
from .ArchGadgetBase import MonitorGadgetFuncExitAbs
from .ArchGadgetBase import CallFunctionAbs, RunCodesAbs, HookFunctionAbs, DynHookAbs, SyscallPatchAbs

class ARM_ArchTranslate(ArchTranslateAbs):
    def get_return_address(self, qlkit):
        return qlkit.reg.lr

    def get_return_value(self, qlkit):
        return qlkit.reg.r0

    def get_args_value(self, qlkit, argnr):
        return getattr(qlkit.reg, "r%d" % argnr)

    def set_ret_value(self, qlkit, retvalue):
        qlkit.reg.r0 = retvalue

    def is_call_inst(self, address, mnemonic, op_str):
        return mnemonic.lower() in ("bl")

class ARM32StackBalance(StackBalance, ARM_ArchTranslate):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.spsize    = 0
        self._old_sp = None

    def env_prepare_assemble(self, old_sp):
        self._old_sp = old_sp
        self.spsize  = 13*4
        asm_list = [
                'stmfd  sp!, {r0-r11,lr}', # 13 regs
        ]
        return asm_list

    def env_recover_assemble(self):
        spaddr = self._old_sp - self.spsize
        asm_list = [
                'mov   r0, #%s' % (spaddr>>16),
                'mov   r1, #%s' % (spaddr&0xffff),
                'add   r0, r1, r0, LSL#16',
                'mov   sp, r0',
                'ldmfd  sp!, {r0-r11, lr}'  # 13 regs
        ]
        return asm_list

    def exit_address_assemble(self, quitaddr):
        asm_list = [
                'str   r0, [sp, #-8]',
                'str   r1, [sp, #-12]',
                'mov   r0, #%s' % (quitaddr>>16),
                'mov   r1, #%s' % (quitaddr&0xffff),
                'add   r0, r1, r0, LSL#16',
                'str   r0, [sp, #-4]',
                'ldr   r0, [sp, #-8]',
                'ldr   r1, [sp, #-12]',
                'ldr   pc, [sp, #-4]',
        ]
        return asm_list

class ARM32_4ArgBase(ARM32StackBalance):
    def __init__(self, funcaddr, **kw):
        super().__init__(**kw)
        self.funcaddr = funcaddr
        self.argnum   = 4
        if 'argnum' in kw:
            self.argnum = kw['argnum']

    def call_sub_func_assemble(self, r0=0, r1=0, r2=0, r3=0):
        asm_list = [
                # set r0 reg
                'mov   r0, #%s' % (r0>>16),
                'mov   r8, #%s' % (r0&0xffff),
                'add   r0, r8, r0, LSL#16',
                # set r1 reg
                'mov   r1, #%s' % (r1>>16),
                'mov   r8, #%s' % (r1&0xffff),
                'add   r1, r8, r1, LSL#16',
                # set r2 reg
                'mov   r2, #%s' % (r2>>16),
                'mov   r8, #%s' % (r2&0xffff),
                'add   r2, r8, r2, LSL#16',
                # set r3 reg
                'mov   r3, #%s' % (r3>>16),
                'mov   r8, #%s' % (r3&0xffff),
                'add   r3, r8, r3, LSL#16',
                # put function addr -> r7
                'mov   r7, #%s' % (self.funcaddr>>16),
                'mov   r8, #%s' % (self.funcaddr&0xffff),
                'add   r7, r8, r7, LSL#16',
                # call function
                'mov   lr, pc',
                'mov   pc, r7',
        ]
        return asm_list, None

class MONITOR_ADDRESS(MonitorCodeAddressAbs, ARM_ArchTranslate):
    pass

class MONITOR_FUNC_EXIT(MonitorGadgetFuncExitAbs, ARM_ArchTranslate):
    pass

class CALL_FUNC(CallFunctionAbs, ARM32_4ArgBase):
    pass

class HookFunction(HookFunctionAbs, ARM_ArchTranslate):
    pass

class DynHookFunction(DynHookAbs, ARM_ArchTranslate):
    pass

class RUNCODES(RunCodesAbs, ARM32StackBalance):
    def call_sub_func_assemble(self, *args):
        asm_list = [
                # put function addr -> r7
                'mov   r7, #%s' % (self.start>>16),
                'mov   r8, #%s' % (self.start&0xffff),
                'add   r7, r8, r7, LSL#16',
                # call function
                'mov   lr, pc',
                'mov   pc, r7',
        ]
        return asm_list, self.end

class PATCH_SYSCALL(SyscallPatchAbs, ARM_ArchTranslate):
    pass
