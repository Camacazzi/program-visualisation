 #!/usr/bin/python
# Modified by Cameron Turner, 2019
#
# Copyright 2017, Sasha Goldshtein.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Feb-2017   Sasha Goldshtein    Created this.

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import json
import os
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest





# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)


def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

exiting = 0
seconds = 0


"""def print_event_perf(cpu,data, size):
    event = b["events"].event(data)
    string = "pid_tgid:"+ str(event.pid_tgid)+ ", pid_tgid32:" +str(event.pid32)+ ",pid name: " +comm_for_pid(event.pid32)+ ", syscall: "+ syscall_name(event.sys) + '\n'
    f = open("outputbpfdata.txt", "w+")
    f.write(string)"""


n = os.fork()
if n == 0: #child
    print("child waiting for signal")
    #signal.pause()
    signal.signal(signal.SIGUSR1, signal_ignore)
    print("signal receieved")
    sleep(0.5)
    print("PID of child is: " + str(os.getpid()))
    
    #sleep(1)
    #delay to let tracing start
    os.execl("./testfork", *sys.argv)
    #run program
    #program end
    os._exit(0)
else: #parent
    #start tracing
    text = """
    #include <uapi/linux/ptrace.h>

    struct data_t{
        u64 ent_pid_tgid; // process id
        u32 ent_pid32; //pid after the 32 bit shift
        u32 ent_sys; // syscall
        u64 ex_pid_tgid; // process id
        u32 ex_pid32; //pid after the 32 bit shift
        u32 ex_sys; // syscall
        u32 ex_ret; //return arguments
    };
    struct data_t_perf{
        u64 time;
        u64 ent_pid_tgid; // process id
        u32 ent_pid32; //pid after the 32 bit shift
        u32 ent_sys; // syscall
        u64 ex_pid_tgid; // process id
        u32 ex_pid32; //pid after the 32 bit shift
        u32 ex_sys; // syscall
        u32 ex_ret; //return arguments
        u64 ip;
    };
    
    struct data_method{
        u64 pid_tgid;
        u32 pid32;
        u64 ip;
    };

    BPF_HASH(data, u64, struct data_t, 500000);
    //BPF_HASH(data_exit_hash, u64, struct data_exit, 500000);
    BPF_HASH(children, u32, u32);

    BPF_HASH(method_ent, u64, struct data_method);

    BPF_PERF_OUTPUT(events);
    //BPF_PERF_OUTPUT(events)

    /*
    TRACEPOINT_PROBE(raw_syscalls,sys_enter){
        struct data_enter val = {};
        //u64 pid_tgid = bpf_get_current_pid_tgid();
        //u32 key32 = pid_tgid >> 32;
        //u32 sys = args->id;
        val.pid_tgid = bpf_get_current_pid_tgid();
        val.pid32 = val.pid_tgid >> 32;
        val.sys = args->id;

        events.perf_submit(args, &val, sizeof(val));

        return 0;
    }*/

    TRACEPOINT_PROBE(raw_syscalls, sys_enter){
        u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        //If pid is not the parents
        if (current_pid != FILTER_PID){
            //check if it belongs to a child
            u32 *check = children.lookup(&current_pid);
            if(check){
                
            }
            else{
                return 0;
            }
        }
        
        

        struct data_t *val, zero= {};
        struct data_t_perf val_perf = {};
        u64 t = bpf_ktime_get_ns();
 
        val = data.lookup_or_try_init(&t, &zero);
        if(val){
            val->ent_pid_tgid = bpf_get_current_pid_tgid();
            val->ent_pid32 = val->ent_pid_tgid >> 32;
            val->ent_sys = args->id;
            val->ex_pid_tgid = 0;
            val->ex_pid32 = 0;
            val->ex_sys = 0;
            val->ex_ret = 0;

            val_perf.time = t;
            val_perf.ent_pid_tgid = val->ent_pid_tgid;
            val_perf.ent_pid32 = val->ent_pid32;
            val_perf.ent_sys = val->ent_sys;
            val_perf.ex_pid_tgid = 0;
            val_perf.ex_pid32 = 0;
            val_perf.ex_sys = 0;
            val_perf.ex_ret = 0;
            val_perf.ip = 0;
            events.perf_submit(args, &val_perf, sizeof(val_perf));
        }
        return 0;
    }

    TRACEPOINT_PROBE(raw_syscalls, sys_exit){
        u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        u32 one = 1;
        u32 clone = 56;
        if (current_pid == FILTER_PID){
            if(args->id == clone){
                u32 ret = args->ret;
                children.lookup_or_try_init(&ret, &one);
            }
        }
        else{
            u32 *check = children.lookup(&current_pid);
                if(check){
                
                }
                else{
                    return 0;
            }
        }
            
        
        struct data_t *val, zero={};
        struct data_t_perf val_perf = {};
        u64 t = bpf_ktime_get_ns();

        val = data.lookup_or_try_init(&t, &zero);
        if(val){
            val->ent_pid_tgid = 0;
            val->ent_pid32 = 0;
            val->ent_sys = 0;
            val->ex_pid_tgid = bpf_get_current_pid_tgid();
            val->ex_pid32 = val->ex_pid_tgid >> 32;
            val->ex_sys = args->id;
            val->ex_ret = args->ret;

            val_perf.time = t;
            val_perf.ent_pid_tgid = 0;
            val_perf.ent_pid32 = 0;
            val_perf.ent_sys = 0;
            val_perf.ex_pid_tgid = val->ex_pid_tgid;
            val_perf.ex_pid32 = val->ex_pid32;
            val_perf.ex_sys = val->ex_sys;
            val_perf.ex_ret = val->ex_ret;
            val_perf.ip = 0;
            events.perf_submit(args, &val_perf, sizeof(val_perf));
        }
        return 0;
    }

    int method_enter(struct pt_regs *ctx){
        u64 t = bpf_ktime_get_ns();
        u64 pid = bpf_get_current_pid_tgid();

        struct data_method *val, zero={};
        //struct data_method_perf val_perf = {};
        struct data_t_perf val_perf = {};
        val = method_ent.lookup_or_try_init(&t, &zero);
        if(val){
            val->pid_tgid = pid;
            val->pid32 = val->pid_tgid >> 32;
            val->ip = PT_REGS_IP(ctx);

            val_perf.time = t;
            val_perf.ent_pid_tgid = val->pid_tgid;
            val_perf.ent_pid32 = val->pid32;
            val_perf.ip = val->ip;

            val_perf.ent_sys = 0;
            val_perf.ex_pid_tgid = 0;
            val_perf.ex_pid32 = 0;
            val_perf.ex_sys = 0;
            val_perf.ex_ret = 0;

            events.perf_submit(ctx, &val_perf, sizeof(val_perf));
        }
        return 0;
    }
    """
    text = ("#define FILTER_PID %d\n" % n) + text

    """out = subprocess.check_output("nm testfork", shell=True)
    out_arr = out.split()
    print(out_arr)
    
    #assuming order of offset, type, name
    #if first variable is not an int, skip to the next int
    #if after finding an int it is all 0, skip to next int
    #if int is non 0, if the symbol is not 'T', skip to next int
    for i in range(out.split):
        if(isinstance(i, int))"""
    filename = "testfork"
    symbols = []
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            #return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        # get .debug_pubtypes section.
        pubnames = dwarfinfo.get_pubnames()
        if pubnames is None:
            print('ERROR: No .debug_pubnames section found in ELF.')
        else:
            print('%d entries found in .debug_pubnames' % len(pubnames))

            # try getting information on a global symbol.
            print('Trying pubnames example ...')
            sym_name = 'main'
            try:
                entry = pubnames[sym_name]
            except KeyError:
                print('ERROR: No pubname entry found for ' + sym_name)
            else:
                print('%s: cu_ofs = %d, die_ofs = %d' %
                        (sym_name, entry.cu_ofs, entry.die_ofs))

                # get the actual CU/DIE that has this information.
                print('Fetching the actual die for %s ...' % sym_name)
                for cu in dwarfinfo.iter_CUs():
                    if cu.cu_offset == entry.cu_ofs:
                        for die in cu.iter_DIEs():
                            if die.offset == entry.die_ofs:
                                print('Die Name: %s' %
                                        bytes2str(die.attributes['DW_AT_name'].value))

            # dump all entries in .debug_pubnames section.
            print('Dumping .debug_pubnames table ...')
            print('-' * 66)
            print('%50s%8s%8s' % ('Symbol', 'CU_OFS', 'DIE_OFS'))
            print('-' * 66)
            for (name, entry) in pubnames.items():
                symbols.append([name])
                print('%50s%8d%8d' % (name, entry.cu_ofs, entry.die_ofs))
                #print(entry)
            print('-' * 66)

            
            for CU in dwarfinfo.iter_CUs():
                for DIE in CU.iter_DIEs():
                    
                    if DIE.tag == 'DW_TAG_subprogram':
                        for i in symbols:
                            print(("i[0]: %20s, die.att: %20s") % (i[0], bytes2str(DIE.attributes['DW_AT_name'].value)))
                            if i[0] == bytes2str(DIE.attributes['DW_AT_name'].value):
                                i.append(DIE.attributes['DW_AT_low_pc'].value)
            print(symbols)




    bpf = BPF(text=text)

    #bpf.attach_uprobe(name="./testfork", sym="writing", fn_name="method_enter")
    #bpf.attach_uprobe(name="./testfork", sym="writing_child", fn_name="method_enter")

    bpf.attach_uretprobe(name="./testfork", sym="writing_child", fn_name="method_enter")
    bpf.attach_uretprobe(name="./testfork", sym="writing", fn_name="method_enter")


    os.kill(n, signal.SIGUSR1)

    def print_event_hash():
        data = bpf["data"]
        method_data = bpf["method_ent"]
        children = bpf["children"]
        for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
            if k.value == 0xFFFFFFFF:
                continue    # happens occasionally, we don't need it
            if(v.ent_pid32 == 0):
                printb((b"exit: %-20d %22s %12d %8d  %20s %15d %15d") % (k.value,comm_for_pid(v.ex_pid32), v.ex_pid32, v.ex_pid_tgid, syscall_name(v.ex_sys), v.ex_sys, v.ex_ret))
            else:
                printb((b"enter: %-20d %22s %12d %8d  %20s %15d") % (k.value, comm_for_pid(v.ent_pid32), v.ent_pid32, v.ent_pid_tgid, syscall_name(v.ent_sys), v.ex_sys))
        for k, v in sorted(method_data.items(), key=lambda kv: -kv[0].value, reverse = True):
            printb((b"method: %-20d %12d %12d %12d %20s") % (k.value, v.pid_tgid, v.pid32, v.ip, bpf.sym(v.ip, v.pid32)))
        for k, v in sorted(children.items(), key=lambda kv: -kv[0].value, reverse = True):
            printb((b"child: %-20d") % (k.value))
    """while True:
        try:
            sleep(0)
        #seconds =+ args.interval
        except KeyboardInterrupt:
            exiting = 1
            print_event_hash()
            signal.signal(signal.SIGINT, signal_ignore)
            #if args.duration and seconds >= args.duration:
            #   exiting = 1

        print_event_hash()
        if exiting or os.waitpid(n, 0) is not n:

            #sleep(0.05)
            #print_event_hash()
            print("Exiting...")
            exit()"""
    
    def print_event_perf(cpu, data, size):
        global start
        sys_event = bpf["events"].event(data)
        #if start == 0:
         #   start = event.ts
        #time_s = (float(event.ts - start)) / 1000000000
        if(sys_event.ent_pid32 == 0 and sys_event.ip == 0):
            #print("exit: %-20d %22s %12d %8d %20s %15d %15d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid_tgid, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret))
            print("exit: %-20d %22s %12d %8d %20s %15d %15d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, sys_event.ex_pid_tgid, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret))
        elif (sys_event.ex_pid32 == 0 and sys_event.ip == 0):
            #print("enter: %-20d %22s %12d %8d %20s %15d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid_tgid, syscall_name(sys_event.ex_sys),sys_event.ex_sys))
            print("enter: %-20d %22s %12d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid_tgid))
        else:
            print("method: %-20d %12d %8d %15s" % (sys_event.time, sys_event.ent_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ent_pid32)))
    
    bpf["events"].open_perf_buffer(print_event_perf)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("KB Interrupt: Exiting...")
            exit()
        #exiting = os.waitpid(n, os.WNOHANG)
        #if os.waitpid(n, os.WNOHANG) is not n:
        if os.waitpid(n, os.WNOHANG) is n:
            #sleep(0.05)
            #print_event_hash()
            bpf.perf_buffer_poll()
            print("Exiting...")
            exit()




