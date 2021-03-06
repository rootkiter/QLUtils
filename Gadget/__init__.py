#!/bin/python
###############################################
# File Name : __init__.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-11 12:40:27 CST
###############################################

from .BuiltIn import GadgetBase
from .BuiltIn import PUSH_NUM, POP_NUM, SET_PC, EXIT, LABEL, REGARCHIVE, MEMPATCH# , CALL_FUNC
from .BuiltIn import STACKALLOC
from .BuiltIn import PUSH_POINTER
from .BuiltIn import GOT_POINTER_INIT
from .BuiltIn import MONITOR_ADDR_READ, MONITOR_ADDR_WRITE
from .BuiltIn import MONITOR_MEM_READ, MONITOR_MEM_WRITE
from .Arch import MipsGadget as MIPS
from .Arch import ArmGadget  as ARM
from .Arch import X686Gadgets  as X686
from .Arch import X8664Gadgets  as X86_64

from .Arch import ArchGadgetAbs, MonitorGadgetAbs, HookFunctionAbs, DynHookAbs
from .Arch import SyscallPatchAbs
from .BuiltIn import BuiltInGadgetAbs
from .BuiltIn import MonitorMemAbs

def ARCHGadgets(qlkit):
    archkey_map = {
            "x86"   : X686      ,
            "x8664" : X86_64    ,
            "mips"  : MIPS      ,
            "arm"   : ARM       ,
            "arm_thumb" : ARM   ,
            "a8086" : X686      ,
    }
    archtype = qlkit.arch_key()

    if archtype not in archkey_map:
        print('didn\'t found match gadgets. %s' % archtype)
        return None
    return archkey_map[archtype]
