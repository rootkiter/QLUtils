from QLUtils.Recombine import addr_tuple
from QLUtils.Recombine import ARCHGadgets
from QLUtils.Recombine import LABEL, PUSH_POINTER

def qlutil_execute_entry(sampath, faddrs, otherargs = None):
    qlkit = QlKit([sampath])
    rcbnRes = RcbnArchive()
    arch = ARCHGadgets(qlkit)

    # your gadgets
    gadgets = [
        LABEL("HELLO"),

        arch.CALL_FUNC(
            "prepare", 0x0400310, 0 # , debug=True
        ),
        PUSH_POINTER("p_enc"),
        arch.CALL_FUNC(
            "decrypt", 0x04003B0, 1 # , debug=True
        )
    ]
    # end your gadgets

    rcbn = Recombine(qlkit, rcbnRes)
    rcbn.emulater_gadgets(
        gadgets, callback_gadgets, None
    )
    return rcbnRes.get_archive("qlutil_quit_result")


# your gadgets callback ..
def callback_gadgets(qlkit, serial, gdt, curr_res, rcbnArchive, userdata):
    print("---> %5s %-20s %s..." % (
        str(serial), gdt.Alias, "%s..." % (str(curr_res)[:40])
    ))

    if gdt.Alias == "prepare_done":
        rcbnArchive.archive("p_enc", curr_res.ret)
    elif gdt.Alias == 'decrypt_done':
        plaintext = qlkit.mem.string(curr_res.ret)
        print(plaintext)

    if serial == 99999:
        # finish
        print("Done. ")

# try don't edit from here...

from QLUtils.Recombine import RcbnArchive
from QLUtils.Recombine import Recombine
from QLUtils.qlkit import QlKit
import sys
if __name__=='__main__':
    func_addrs = addr_tuple(
    )
    sampath = "QLUtils/examples/src/sample_bin.mips"

    result = qlutil_execute_entry(
            sampath, func_addrs, None
    )
    print("done")
    print(result)
