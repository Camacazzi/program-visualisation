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


def print_event_perf(cpu,data, size):
    event = b["events"].event(data)
    string = "pid_tgid:"+ str(event.pid_tgid)+ ", pid_tgid32:" +str(event.pid32)+ ",pid name: " +comm_for_pid(event.pid32)+ ", syscall: "+ syscall_name(event.sys) + '\n'
    f = open("outputbpfdata.txt", "w+")
    f.write(string)

"""b["events"].open_perf_buffer(print_event_perf)
while 1:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        exit()"""
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
    
    struct data_method{
        u64 pid_tgid;
        u32 pid32;
        u64 ip;
    };

    BPF_HASH(data, u64, struct data_t, 500000);
    //BPF_HASH(data_exit_hash, u64, struct data_exit, 500000);
    BPF_HASH(children, u32, u32);

    BPF_HASH(method_ent, u64, struct data_method);

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

    int method_enter(struct pt_regs *ctx){
        u64 t = bpf_ktime_get_ns();
        u64 pid = bpf_get_current_pid_tgid();

        struct data_method *val, zero={};
        val = method_ent.lookup_or_try_init(&t, &zero);
        if(val){
            val->pid_tgid = pid;
            val->pid32 = val->pid_tgid >> 32;
            val->ip = PT_REGS_IP(ctx);
        }
        return 0;
    }
    """
    text = ("#define FILTER_PID %d\n" % n) + text

    out = subprocess.check_output("nm testfork", shell=True)

    print(out.split())

    bpf = BPF(text=text)

    bpf.attach_uprobe(name="./testfork", sym="writing", fn_name="method_enter")
    bpf.attach_uprobe(name="./testfork", sym="writing_child", fn_name="method_enter")


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
            printb((b"method: %-20d %12d %12d %12d") % (k.value, v.pid_tgid, v.pid32, v.ip))
        for k, v in sorted(children.items(), key=lambda kv: -kv[0].value, reverse = True):
            printb((b"child: %-20d") % (k.value))
    while True:
        try:
            sleep(0)
        #seconds =+ args.interval
        except KeyboardInterrupt:
            exiting = 1
            print_event_hash()
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





