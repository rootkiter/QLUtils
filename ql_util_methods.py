#!/bin/python
###############################################
# File Name : QLUtils/ql_syscall_lib.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-18 15:38:40 CST
###############################################

from .Gadget import LABEL, GOT_POINTER_INIT
from .Gadget import ARCHGadgets
from . import ql_libc_methods
from . import ql_syscall_methods

def load_libc_dyn_methods(lib_methods):
    methods_map = {}
    for obj_name in dir(lib_methods):
        method = getattr(lib_methods, obj_name)
        if hasattr(method, "funcname") and hasattr(method, "argnum"):
            methods_map[method.funcname] = (method.argnum, method)
    return methods_map

def dyn_start_default_gadgets(qlkit, libc_addrs=None):
    arch = ARCHGadgets(qlkit)
    dyn_methods = load_libc_dyn_methods(ql_libc_methods)

    gadgets = [
        GOT_POINTER_INIT("__stack_chk_guard"),
    ]

    loaded_names = []

    if libc_addrs != None:
        for name in libc_addrs._fields:
            if name not in dyn_methods:
                continue
            loaded_names.append(name)
            addr = getattr(libc_addrs, name)
            argnum, new_method = dyn_methods[name]
            gadgets.append(
                    arch.HookFunction(name, addr, new_method, argnum, no_cbk=False)
            )
    for dyn_name in dyn_methods:
        if dyn_name in loaded_names:
            continue
        argnum, new_method = dyn_methods[dyn_name]
        gadgets.append(
            arch.DynHookFunction(dyn_name, new_method, argnum, no_cbk=False)
        )

    return gadgets

def sys_start_default_gadgets(qlkit):
    arch = ARCHGadgets(qlkit)
    sys_methods = load_libc_dyn_methods(ql_syscall_methods)

    gadgets = [ ]

    for sys_name in sys_methods:
        argnum, new_method = sys_methods[sys_name]
        gadgets.append(
            arch.PATCH_SYSCALL(sys_name, new_method, argnum)
        )

    return gadgets

from qiling.const import QL_INTERCEPT

def get_util_gadgets(qlkit, libc_addrs=None):
    dyn_gadgets = dyn_start_default_gadgets(qlkit, libc_addrs)
    sys_gadgets = sys_start_default_gadgets(qlkit)
    gadgets =  dyn_gadgets + sys_gadgets

    # qlkit.set_syscall("socketcall", get_params, QL_INTERCEPT.CALL)
    return gadgets

