#!/bin/python
###############################################
# File Name : Aworker/AWorker/sdk/utillib/QLUtils/ql_syscall_methods.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-11-29 13:00:58 CST
###############################################

def _sys_decorator(funcname, argnum):
    def real_func(func):
        def inner(*args):
            retargs = args[1:]
            retname = funcname
            ret = func(*args)
            while isinstance(ret, tuple):
                retname, retargs, ret = ret
            return retname, retargs, ret
        setattr(inner, "funcname", funcname)
        setattr(inner, "argnum"  , argnum  )
        return inner
    return real_func

@_sys_decorator("socket", 3)
def sys_socket(qlkit, int_domain, int_type, int_protocol):
    return 0x4141

@_sys_decorator("connect", 3)
def sys_connect(qlkit, sockfd, p_addr, adrsize):
    return 0

@_sys_decorator("send", 4)
def sys_send(qlkit, sockfd, p_buf, size, flags):
    return size

@_sys_decorator("recv", 4)
def sys_recv(qlkit, sockfd, p_buf, size, flags):
    return size

@_sys_decorator("fcntl", 3)
def sys_fcntl(qlkit, sockfd, arg2, arg3):
    return 1

@_sys_decorator("fcntl64", 3)
def sys_fcntl(qlkit, sockfd, arg2, arg3):
    return 1

@_sys_decorator("socketcall", 2)
def sys_socketcall(qlkit, call_no, p_args):
    SOCKETCALL_SYS_SOCKET  = 1
    SOCKETCALL_SYS_BIND    = 2
    SOCKETCALL_SYS_CONNECT = 3
    SOCKETCALL_SYS_LISTEN  = 4
    SOCKETCALL_SYS_ACCEPT  = 5
    SOCKETCALL_SYS_GETSOCKNAME = 6
    SOCKETCALL_SYS_GETPEERNAME = 7
    SOCKETCALL_SYS_SOCKETPAIR  = 8
    SOCKETCALL_SYS_SEND        = 9
    SOCKETCALL_SYS_RECV        = 10
    SOCKETCALL_SYS_SENDTO      = 11
    SOCKETCALL_SYS_RECVFROM    = 12
    SOCKETCALL_SYS_SHUTDOWN    = 13
    SOCKETCALL_SYS_SETSOCKOPT  = 14
    SOCKETCALL_SYS_GETSOCKOPT  = 15
    SOCKETCALL_SYS_SENDMSG     = 16
    SOCKETCALL_SYS_RECVMSG     = 17
    SOCKETCALL_SYS_ACCEPT4     = 18
    SOCKETCALL_SYS_RECVMMSG    = 19
    SOCKETCALL_SYS_SENDMMSG    = 20

    # map call values to their corresponding handlers and number of arguments they
    # should read from the specified base pointer
    handlers = {
        SOCKETCALL_SYS_SOCKET      : sys_socket,
        SOCKETCALL_SYS_CONNECT     : sys_connect,
        SOCKETCALL_SYS_SEND        : sys_send,
        # SOCKETCALL_SYS_RECVFROM    : (ql_syscall_recvfrom, 6),
        # SOCKETCALL_SYS_SENDTO      : (ql_syscall_sendto, 6),
        # SOCKETCALL_SYS_RECV        : (ql_syscall_recv, 4),
        # SOCKETCALL_SYS_BIND        : (ql_syscall_bind, 3),
        # SOCKETCALL_SYS_LISTEN      : (ql_syscall_listen, 2),
        # SOCKETCALL_SYS_ACCEPT      : (ql_syscall_accept, 3),
        # SOCKETCALL_SYS_GETSOCKNAME : (ql_syscall_getsockname, 3),
        # SOCKETCALL_SYS_SETSOCKOPT  : (ql_syscall_setsockopt, 5)
    }
    if not isinstance(call_no, int) or call_no not in handlers:
        print("sys_socketcall not contains [%s]" % str(call_no))
        return 0
    method = handlers[call_no]
    nargs = method.argnum
    params = (
        qlkit.unpack(qlkit.mem.read(p_args + i * qlkit.pointersize, qlkit.pointersize)) \
            for i in range(nargs)
    )
    return method(qlkit, *params)

