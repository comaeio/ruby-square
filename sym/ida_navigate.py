from idaapi import *
from idc import *
import collections

INDEX = 0
ADDRS = []
ADDRS_MAP = {}  # mapping from address to index(es) in 'ADDRS'

Context = collections.namedtuple('Context', 'addr')

def process_context(context):
    jumpto(context.addr)

def first_trace_addr():
    global ADDRS
    global INDEX

    INDEX = 0
    process_context(ADDRS[INDEX])

def last_trace_addr():
    global ADDRS
    global INDEX

    INDEX = len(ADDRS) - 1
    process_context(ADDRS[INDEX])

def next_trace_addr():
    global ADDRS
    global INDEX

    if INDEX + 1 == len(ADDRS):
        print "Last address"
    else:
        INDEX += 1
        process_context(ADDRS[INDEX])

def prev_trace_addr():
    global ADDRS
    global INDEX

    if INDEX == 0:
        print "First address"
    else:
        INDEX -= 1
        process_context(ADDRS[INDEX])

def goto_trace_addr():
    global ADDRS
    global ADDRS_MAP
    global INDEX

    addr = AskAddr(here(), "Go to address in trace")

    indexes = ADDRS_MAP.get(addr)

    if not indexes:
        print "Failed to find address"

    elif len(indexes) == 1:
        INDEX = indexes[0]
        process_context(ADDRS[INDEX])

    else:
        i = AskLong(0, "Multiple matches found, choose index: 0-{}"
                .format(len(indexes) - 1))

        if not i in range(len(indexes)):
            print "Invalid index"

        else:
            INDEX = indexes[i]
            process_context(ADDRS[INDEX])

def show_command_list():
    print "Commands:"
    print "---------"
    print "H -- show command list"
    print "0 -- first address in trace"
    print "$ -- last address in trace"
    print "j -- next address in trace"
    print "k -- previous address in trace"
    print "G -- go to address in trace"

def main():
    global TRACE_FILE
    global ADDRS
    global ADDRS_MAP
    global Context
    global first_trace_addr
    global last_trace_addr
    global next_trace_addr
    global prev_trace_addr

    TRACE_FILE = AskFile(0, "*.trace", "Select trace file")
    if not TRACE_FILE:
        Warning("Failed to select trace file")
        return

    with open(TRACE_FILE) as lines:
        print "Processing trace..."
        for i, line in enumerate(lines):
            line = line.strip()
            addr = int(line, 16)
            context = Context(addr)
            ADDRS.append(context)

            if not ADDRS_MAP.get(addr):
                ADDRS_MAP[addr] = []

            ADDRS_MAP[addr].append(i)
            # print "addr: 0x{:x}".format(addr)
        print "Done"

    if len(ADDRS) == 0:
        Warning("No addresses found")
        return

    idaapi.compile_idc_text('static show_command_list() { RunPythonStatement("show_command_list()"); }')
    idaapi.compile_idc_text('static first_trace_addr() { RunPythonStatement("first_trace_addr()"); }')
    idaapi.compile_idc_text('static last_trace_addr() { RunPythonStatement("last_trace_addr()"); }')
    idaapi.compile_idc_text('static next_trace_addr() { RunPythonStatement("next_trace_addr()"); }')
    idaapi.compile_idc_text('static prev_trace_addr() { RunPythonStatement("prev_trace_addr()"); }')
    idaapi.compile_idc_text('static goto_trace_addr() { RunPythonStatement("goto_trace_addr()"); }')

    # To delete: 'del_idc_hotkey(<KEY>)'.
    add_idc_hotkey("Shift-h", "show_command_list")
    add_idc_hotkey("0", "first_trace_addr")
    add_idc_hotkey("$", "last_trace_addr")
    add_idc_hotkey("j", "next_trace_addr")
    add_idc_hotkey("k", "prev_trace_addr")
    add_idc_hotkey("Shift-g", "goto_trace_addr")

    show_command_list()

main()
