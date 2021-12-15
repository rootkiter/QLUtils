#!/bin/python
###############################################
# File Name : Aworker/AWorker/sdk/utillib/QLUtils/ql_libc_methods.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-11-25 11:50:28 CST
###############################################

def _dyn_decorator(funcname, argnum):
    def real_func(func):
        def inner(*args, **kwargs):
            return func(*args, **kwargs)
        setattr(inner, "funcname", funcname)
        setattr(inner, "argnum"  , argnum  )
        return inner
    return real_func

@_dyn_decorator("memset", 3)
def dyn_memset(qlkit, void_p_buf, int_c, size_t_n):
    tmpbuf = bytes([int_c] * size_t_n)
    qlkit.mem.write(void_p_buf, tmpbuf)
    return void_p_buf

@_dyn_decorator("memcpy", 3)
def dyn_memcpy(qlkit, void_p_dest, void_p_src, size_t_n):
    tmpbuf = qlkit.mem.read(void_p_src, size_t_n)
    qlkit.mem.write(void_p_dest, bytes(tmpbuf))
    return void_p_dest

@_dyn_decorator("__strcpy_chk", 3)
def dyn___strcpy_chk(qlkit, void_p_dest, void_p_src, size_t_n):
    if void_p_src == 0:
        return 0
    tmpbuf = qlkit.mem.string(void_p_src)
    cpsize = size_t_n
    if len(tmpbuf) < size_t_n:
        cpsize = len(tmpbuf)
    nvalue = dyn_memcpy(qlkit, void_p_dest, void_p_src, cpsize)
    return nvalue

@_dyn_decorator("strchr", 2)
def dyn_strchr(qlkit, void_p_buf, int_c):
    tmpbuf = qlkit.mem.string(void_p_buf)
    for i in range(0, len(tmpbuf)):
        if int(ord(tmpbuf[i])) == int(int_c):
            return void_p_buf + i
    return 0

@_dyn_decorator("strlen", 1)
def dyn_strlen(qlkit, void_p_buf):
    if void_p_buf != 0:
        return len(qlkit.mem.string(void_p_buf))
    return 0

@_dyn_decorator("free", 1)
def dyn_free(qlkit, void_p_buf):
    return 0


@_dyn_decorator("fcntl", 3)
def dyn_fcntl(qlkit, *args):
    return 0x80

@_dyn_decorator("inet_addr", 1)
def dyn_inet_addr(qlkit, p_ip):
    ip = qlkit.mem.string(p_ip)
    print("inet_addr(%s)" % ip)
    ret = 0
    tmp = ip.split('.')
    if len(tmp) != 4:
        return ret
    for i in tmp[::-1]:
        ret = ret * 0x100 + int(i)
    return ret

@_dyn_decorator("malloc", 1)
def dyn_malloc(qlkit, size):
    return qlkit.mem_heap_alloc(size)

@_dyn_decorator("calloc", 2)
def dyn_calloc(qlkit, nmemb, size):
    return qlkit.mem_heap_alloc(nmemb * size)

@_dyn_decorator("realloc", 2)
def dyn_realloc(qlkit, ptr, size):
    new_buf = qlkit.mem_heap_alloc(size)
    if new_buf == None:
        return 0
    if ptr != 0:
        olddata = qlkit.mem.read(ptr, size)
        qlkit.mem.write(new_buf, bytes(olddata))
    return new_buf

@_dyn_decorator("strtol", 3)
def dyn_strtol(qlkit, p_str, p_p_endptr, base):
    tmpstr = qlkit.mem.string(p_str)
    dstr = tmpstr.split()[0]
    dvalue = int(dstr, base)
    endptr = len(dstr) + p_str
    if p_p_endptr != 0:
        qlkit.mem.write(p_p_endptr, qlkit.pack(endptr))
    return dvalue

@_dyn_decorator("socket", 3)
def dyn_socket(qlkit, int_domain, int_type, int_protocol):
    return 0x4141

@_dyn_decorator("connect", 3)
def dyn_connect(qlkit, sockfd, p_sockaddr, socklen):
    return 1


