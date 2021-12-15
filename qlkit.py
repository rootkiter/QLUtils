#!/bin/python
###############################################
# File Name : new_test/qlkit.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2021-06-09 12:04:30 CST
###############################################

import qiling, os
from qiling.utils import ql_guess_emu_env
from qiling.utils import ostype_convert_str, arch_convert_str
from qiling.const import QL_ENDIAN, QL_INTERCEPT, QL_CALL_BLOCK
from elftools.elf.elffile import ELFFile

endian_map = {
        QL_ENDIAN.EL: "LSB",
        QL_ENDIAN.EB: "MSB",
}

def file_need_env(binpath):
    arch, ost, endian = ql_guess_emu_env(binpath)
    arch = arch_convert_str(arch)
    ost = ostype_convert_str(ost)
    endian = endian_map[endian]

    #  linux libc? uClibc? ...
    envlib = 'libc'
    if 'linux' == ost:
        f = open(binpath, 'rb')
        elfdata = f.read().ljust(52, b'\x00')
        elffile = ELFFile(open(binpath, 'rb'))
        for seg in elffile.iter_segments():
            if seg['p_type'] != 'PT_INTERP':
                continue
            start = seg['p_offset']
            end   = start + seg['p_filesz']
            ldname = elfdata[start:end]
            ldname = (ldname[: ldname.find(b'\x00')].decode('utf-8'))
            if 'uClibc' in ldname:
                envlib = 'uClibc'
    return (arch, ost, endian, envlib)

def try_get_key_str(binpath):
    arch, ost, endian, envlib = file_need_env(binpath)
    keystr = "%s_%s_%s_%s" % (
            arch, ost, endian, envlib
    )
    print("filekey -> ", keystr)
    return True, keystr

class QlKit(qiling.Qiling):
    def __init__(self, sam_argv, **kw):
        self.sam_argv = sam_argv
        self.lasttraceaddr = 0 
        if len(sam_argv) < 1:
            return None
        self.sampath = sam_argv[0]
        ok, self.keystr = try_get_key_str(self.sampath)
        if not ok:
            return None
        super().__init__(self.sam_argv, ".", **kw)
        self.elffile = ELFFile(open(self.sampath, 'rb'))

    def set_got_value(self, sym_name, value):
        func_hook = self.os.function_hook
        if func_hook.mips_gotsym != None and \
            func_hook.mips_symtabno != None and \
            func_hook.strtab != None:
            for symidx in range(
                func_hook.mips_gotsym, func_hook.mips_symtabno
            ):
                sym_elf = func_hook.symtab[symidx]
                rel_name = func_hook.strtab[sym_elf.st_name]
                if rel_name != sym_name.encode():
                    continue
                sym_off = (symidx - func_hook.mips_gotsym +
                        func_hook.mips_local_gotno)
                addr = func_hook.load_base + func_hook.plt_got+ sym_off * self.archbytes
                tmpbuf = self.pack(value)
                self.mem.write(addr, tmpbuf)
                return addr, tmpbuf
        return None, None


    @property
    def archbytes(self):
        if self.archbit == 32:
            return 4
        return 8

    def arch_key(self):
        return self.keystr

    def trace_everyinst(self, start, end, print_msg=True):
        bin_code_buf = self.mem.read(start, end-start)
        insts = self.disassembler.disasm(bin_code_buf, start)
        codelists = []
        for inst in insts:
            hexstr = "".join(map(lambda x: "%02x" % x, inst.bytes))
            codelists.append((inst.address, hexstr, inst.mnemonic, inst.op_str))
        def on_bp_every_inst(ql, instarg):
            addr   = instarg['addr']
            hexstr = instarg['hex']
            mnem   = instarg['mnem']
            opstr  = instarg['opstr']
            hook_t = instarg['hook']
            self.lasttraceaddr = addr
            if print_msg:
                print("%-10s %-20s %s %s" % (hex(addr), hexstr, mnem, opstr))
            if hook_t:
                hook_t.remove()
        for addr, hexstr, mnem, opstr in codelists:
            argmap = {
                    "addr" : addr,
                    "hex"  : hexstr,
                    "mnem" : mnem,
                    'opstr': opstr,
                    'hook' : None,
            }
            hook_t = self.hook_address(on_bp_every_inst, addr, argmap)
            argmap['hook'] = hook_t

    def my_syscall_patch(self, target, callback, userdata):
        cbf = lambda *a, **kw: callback(userdata, *a, **kw)
        self.set_syscall(target, cbf)

    def mem_heap_alloc(self, size):
        if not hasattr(self.os, 'heap'):
            stack_address = self.loader.stack_address
            heap_size = 0x0050000
            heapaddr = self.mem.find_free_space( heap_size, minaddr=stack_address)
            if heapaddr <= 0:
                return None
            from qiling.os.memory import QlMemoryHeap
            heap = QlMemoryHeap(self, heapaddr, heapaddr + heap_size)
            setattr(self.os, 'heap', heap)
        address = self.os.heap.alloc(size)
        return address

    def mem_align_alloc(self, size, align=4):
        needsize = size + align
        tmpstart = self.mem_heap_alloc(needsize)
        return (tmpstart - (tmpstart % 4))

    def my_hook_code(self, address, callback, userarg, trigger_once=True):
        def on_cbf(ql, address, size, arginside):
            cbk    = arginside['cbk']
            uargs  = arginside['args']
            once   = arginside['once']
            hook_t = arginside['hook']
            cbk(ql, address, uargs)
            try:
                if once:
                    hook_t.remove()
            except Exception as e:
                print(str(e))

        argmap = {
                'cbk' : callback,
                'args': userarg ,
                'once': trigger_once,
                'hook': None
        }

        hook_t = self.hook_code(on_cbf, argmap, begin=address, end=address)
        argmap['hook'] = hook_t

    def addr_belongs_stack(self, address):
        # code-resource: qiling/profiles/linux.ql
        if self.loader.stack_address > address and \
            self.loader.stack_address - address < 0x30000:
                return True
        return False

    def addr_belongs_binary(self, address):
        saminfo = self.path
        for mem_item in self.mem.map_info:
            mem_s, mem_e, mem_p, mem_info, is_mmio = mem_item
            if mem_info != saminfo:
                continue
            if address >= mem_s and address <= mem_e:
                return True
        return False

    def _sh_segment(self, address):
        for segment in self.elffile.iter_segments():
            p_offset = segment.header['p_offset']
            p_memsz  = segment.header['p_memsz']
            if address >= p_offset and address < p_offset + p_memsz:
                p_vaddr = segment.header['p_vaddr']
                return (p_offset, p_memsz, p_vaddr)
        return None

    def addr_belongs_section_name(self, address):
        # print (hex(self.loader.elfhead['e_ehsize']))
        # print( self.loader .parse_header())
        for section in self.elffile.iter_sections():
            if section.header['sh_flags'] & 2:
                secname = section.name
                offaddr = section.header['sh_offset']
                secsize = section.header['sh_size']
                seginfo = self._sh_segment(offaddr)
                if seginfo == None:
                    continue
                off, sz, vaddr = seginfo
                secaddr = offaddr - off + vaddr

                if address >= secaddr and address < secaddr + secsize:
                    return secname
        return None

    def hook_dyn_function(self, funcname, callback, userdata = None):
        def cbk_inside(qlkit):
            callback(qlkit, userdata)
        self.os.function_hook.add_function_hook(
                funcname, cbk_inside, QL_INTERCEPT.CALL
        )

    def my_emu_start(self, begin = None, end = None):
        if not self.can_emulator():
            return False
        def intr_echo(qlkit, *args):
            print("intr", qlkit, hex(qlkit.reg.arch_pc), args)
            pass
        self.hook_intno(intr_echo, 12)
        self.hook_intno(intr_echo, 15)
        self.emu_start(begin, end)

    def segments_check(self):
        from elftools.elf.sections import SymbolTableSection
        ld_segments = tuple(seg for seg in self.elffile.iter_segments() if seg['p_type'] == 'PT_LOAD')
        for seg in ld_segments:
            if seg['p_vaddr'] != seg['p_paddr']:
                errmsg = "The file's segment is illegal. "+ \
                        "[%s %s p_vaddr:%s != p_paddr:%s]" % (
                                self.sampath, seg['p_type'], 
                                hex(seg['p_vaddr']), hex(seg['p_paddr'])
                        )
                print(errmsg)
                return False
        return True
            # print(hex( seg['p_vaddr']), hex(seg['p_paddr']))


    def can_emulator(self):
        return self.segments_check()

    def symbols_iterator(self):
        from elftools.elf.sections import SymbolTableSection
        symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]
        for section in symbol_tables:
            if section['sh_entsize'] == 0:
                continue
            for nsym, symbol in enumerate(section.iter_symbols()):
                if (symbol['st_info']['type']) != 'STT_FUNC':
                    continue
                addr = symbol.entry.st_value
                yield (symbol.name, addr)

    def get_symbol_addr(self, sym_addr):
        try:
            for name, addr in self.symbols_iterator():
                if addr == sym_addr:
                    return name
        except Exception as e:
            print(str(e))
        return None
        

    def find_symbols_name(self, sym_name):
        try:
            for name, addr in self.symbols_iterator():
                if name == sym_name:
                    return addr
        except Exception as e:
            print(str(e))
        return None

def on_test_cbf(qlkit, address, userarg):
    print(qlkit, address, userarg)

def arm_test():
    handle = QlKit(['/root/mydbg/samples/tt.arm'])
    handle.trace_everyinst(0x0008204, 0x000008220, False)
    handle.run()

def mips_test():
    handle = QlKit(['/root/mydbg/new_rootfs/mips32_linux/bin/mips32_hello'])
    handle.run()

import sys
if __name__=='__main__':
    # arm_test()
    mips_test()
