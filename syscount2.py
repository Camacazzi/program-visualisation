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


parser = argparse.ArgumentParser(
    description="Summarize syscall counts and latencies.")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")



parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed syscalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only syscalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()

text = """

//have a map wiith a meaningless key at the beginning, and in each leaf have the
//syscall name, PID, pid_tgid>>32


struct data_t{
    u64 pid_tgid; // process id
    u32 pid32; //pid after the 32 bit shift
    u32 sys; // syscall
};

struct data_exit {
    u64 pid_tgid; // process id
    u32 pid32; //pid after the 32 bit shift
    u32 sys; // syscall
    u32 ret; //return arguments
};

//BPF_HASH(count, u32, u32);
BPF_HASH(data, u64, struct data_t, 500000);
BPF_HASH(data_exit_hash, u64, struct data_exit, 500000);


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
    struct data_t *val, zero= {};
    u64 t = bpf_ktime_get_ns();
    val = data.lookup_or_init(&t, &zero);
    
    if(val){
        val->pid_tgid = bpf_get_current_pid_tgid();
        val->pid32 = val->pid_tgid >> 32;
        val->sys = args->id;
    }
    

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit){
    struct data_exit *val, zero={};
    u64 t = bpf_ktime_get_ns();
    val = data_exit_hash.lookup_or_init(&t, &zero);
    if(val){
        val->pid_tgid = bpf_get_current_pid_tgid();
        val->pid32 = val->pid_tgid >> 32;
        val->sys = args->id;
        val->ret = args->ret;
    }

    return 0;
}
"""

if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

#agg_colname = "PID    COMM" if args.process else "SYSCALL"
#time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

print("Tracing %ssyscalls, printing top %d... Ctrl+C to quit.")
exiting = 0
seconds = 0


def print_event_perf(cpu,data, size):
    event = b["events"].event(data)
    string = "pid_tgid:"+ str(event.pid_tgid)+ ", pid_tgid32:" +str(event.pid32)+ ",pid name: " +comm_for_pid(event.pid32)+ ", syscall: "+ syscall_name(event.sys) + '\n'
    f = open("outputbpfdata.txt", "w+")
    f.write(string)

def print_event_hash():
    data = bpf["data"]
    #string = "pid_tgid:"+ str(data.pid_tgid)+ ", pid_tgid32:" +str(data.pid32)+ ",pid name: " +comm_for_pid(data.pid32)+ ", syscall: "+ syscall_name(data.sys) + '\n'
    for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-20d %22s %8d  %20s") % (k.value, comm_for_pid(v.pid32), v.pid_tgid, syscall_name(v.sys)))
    print("STARTING EXIT PRINT")
    data = bpf["data_exit_hash"]
    for k, v in sorted(data.items(), key=lambda kv: -kv[0].value, reverse = True):
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-20d %22s %8d  %20s %15d") % (k.value, comm_for_pid(v.pid32), v.pid_tgid, syscall_name(v.sys), v.ret))

"""b["events"].open_perf_buffer(print_event_perf)
while 1:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        exit()"""

while True:
    try:
        sleep(0)
        #seconds =+ args.interval
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    #if args.duration and seconds >= args.duration:
    #   exiting = 1

    print_event_hash()
    if exiting:
        print("Exiting...")
        exit()