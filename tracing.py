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


"""parser = argparse.ArgumentParser(description="Summarize syscall counts and latencies.")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")


parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed syscalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only syscalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()"""



"""if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.ebpf:
    print(text)
    exit()"""

#bpf = BPF(text=text)

#agg_colname = "PID    COMM" if args.process else "SYSCALL"
#time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

exiting = 0
seconds = 0


def print_event_perf(cpu,data, size):
    event = b["events"].event(data)
    string = "pid_tgid:"+ str(event.pid_tgid)+ ", pid_tgid32:" +str(event.pid32)+ ",pid name: " +comm_for_pid(event.pid32)+ ", syscall: "+ syscall_name(event.sys) + '\n'
    f = open("outputbpfdata.txt", "w+")
    f.write(string)

"""def print_event_hash():
    data = bpf["data"]
    #string = "pid_tgid:"+ str(data.pid_tgid)+ ", pid_tgid32:" +str(data.pid32)+ ",pid name: " +comm_for_pid(data.pid32)+ ", syscall: "+ syscall_name(data.sys) + '\n'
    #sorting for earliest first
    for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-20d %22s %8d  %20s") % (k.value, comm_for_pid(v.pid32), v.pid_tgid, syscall_name(v.sys)))
    print("STARTING EXIT PRINT")
    data = bpf["data_exit_hash"]
    #sorting for earliest first
    for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-20d %22s %8d  %20s %15d") % (k.value, comm_for_pid(v.pid32), v.pid_tgid, syscall_name(v.sys), v.ret))"""

"""b["events"].open_perf_buffer(print_event_perf)
while 1:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        exit()"""
n = os.fork()
if n == 0: #child
    sleep(1)
    print("PID of child is: " + str(os.getpid()))
    
    sleep(1)
    #delay to let tracing start
    os.execl("./testfork", *sys.argv)
    #run program
    #program end
    os._exit(0)
else: #parent
    #start tracing
    text = """

    //have a map wiith a meaningless key at the beginning, and in each leaf have the
    //syscall name, PID, pid_tgid>>32


    struct data_t{
        u64 ent_pid_tgid; // process id
        u32 ent_pid32; //pid after the 32 bit shift
        u32 ent_sys; // syscall
        u64 ex_pid_tgid; // process id
        u32 ex_pid32; //pid after the 32 bit shift
        u32 ex_sys; // syscall
        u32 ex_ret; //return arguments
    };

    /*struct data_exit {
        u64 pid_tgid; // process id
        u32 pid32; //pid after the 32 bit shift
        u32 sys; // syscall
        u32 ret; //return arguments
    };*/

    //BPF_HASH(count, u32, u32);
    BPF_HASH(data, u64, struct data_t, 500000);
    //BPF_HASH(data_exit_hash, u64, struct data_exit, 500000);
    BPF_HASH(children, u32, u32);


    //BPF_PERF_OUTPUT(events);
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
        if (current_pid != FILTER_PID){
            u32 *check = children.lookup(&current_pid);
            if(check){
                
            }
            else{
                return 0;
            }
        }
        
        

        struct data_t *val, zero= {};
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
        }
        return 0;
    }

    TRACEPOINT_PROBE(raw_syscalls, sys_exit){
        u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        u32 one = 1;
        u32 clone = 56;
        if (bpf_get_current_pid_tgid() >> 32 != FILTER_PID){
            if(args->id == clone){
                children.lookup_or_try_init(&current_pid, &one);
                return 0;
            }
            else{
                u32 *check = children.lookup(&current_pid);
                if(check){
                
                }
                else{
                    return 0;
                }
            }
        }
            
        
        struct data_t *val, zero={};
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
        }
        return 0;
    }
    """
    text = ("#define FILTER_PID %d\n" % n) + text

    bpf = BPF(text=text)

    def print_event_hash():
        data = bpf["data"]
        #string = "pid_tgid:"+ str(data.pid_tgid)+ ", pid_tgid32:" +str(data.pid32)+ ",pid name: " +comm_for_pid(data.pid32)+ ", syscall: "+ syscall_name(data.sys) + '\n'
        #sorting for earliest first
        """for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
            if k.value == 0xFFFFFFFF:
                continue    # happens occasionally, we don't need it
            printb((b"%-20d %22s %12d %8d  %20s") % (k.value, comm_for_pid(v.pid32), v.pid32, v.pid_tgid, syscall_name(v.sys)))
        print("STARTING EXIT PRINT")"""
        #sorting for earliest first
        #for i in data.items():
        #    print(i)
        for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
            if k.value == 0xFFFFFFFF:
                continue    # happens occasionally, we don't need it
            if(v.ent_pid32 == 0):
                printb((b"exit: %-20d %22s %12d %8d  %20s %15d %15d") % (k.value,comm_for_pid(v.ex_pid32), v.ex_pid32, v.ex_pid_tgid, syscall_name(v.ex_sys), v.ex_sys, v.ex_ret))
            else:
                printb((b"enter: %-20d %22s %12d %8d  %20s %15d") % (k.value, comm_for_pid(v.ent_pid32), v.ent_pid32, v.ent_pid_tgid, syscall_name(v.ent_sys), v.ex_sys))
    while True:
        try:
            sleep(0)
        #seconds =+ args.interval
        except KeyboardInterrupt:
            exiting = 1
            signal.signal(signal.SIGINT, signal_ignore)
            #if args.duration and seconds >= args.duration:
            #   exiting = 1

        #print_event_hash()
        if exiting or os.waitpid(n, 0) is not n:

            #sleep(0.05)
            print_event_hash()
            print("Exiting...")
            exit()
    
    print("have returned successfully, child pid was: "+ str(n))





