from idaapi import *
from idc import *

def main():
    highlight = AskLong(0, "Choose action: 0 = clear, 1 = highlight")

    if not highlight in [0, 1]:
        Warning("Invalid action: {}".format(highlight))
        return

    color = 0xccccff if highlight == 1 else 0xffffff

    if highlight == 1:
        trace_file = AskFile(0, "*.trace", "Select trace file")
        if not trace_file:
            Warning("Failed to select trace file")
            return

        with open(trace_file) as lines:
            print "Highlighting..."
            for line in lines:
                line = line.strip()
                addr = int(line, 16)
                idc.SetColor(addr, idc.CIC_ITEM, color)
            print "Done"

    else:
        print "Clearing..."
        addr = 0
        while addr != 0xffffffff:
            idc.SetColor(addr, idc.CIC_ITEM, color)
            addr = next_addr(addr)
        print "Done"

main()
