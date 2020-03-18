 
#!/usr/bin/python
#
# syscount   Summarize syscall counts and latencies.
#
# USAGE: syscount [-p PID] [-i INTERVAL] [-T TOP] [-x] [-L] [-m] [-P] [-l]
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
parser.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--top", type=int, default=10,
    help="print only the top syscalls by count or latency")
parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed syscalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only syscalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("-L", "--latency", action="store_true",
    help="collect syscall latency")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display latency in milliseconds (default: microseconds)")
parser.add_argument("-P", "--process", action="store_true",
    help="count by process and not by syscall")
parser.add_argument("-l", "--list", action="store_true",
    help="print list of recognized syscalls and exit")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

if args.list:
    for grp in izip_longest(*(iter(sorted(syscalls.values())),) * 4):
        print("   ".join(["%-20s" % s for s in grp if s is not None]))
    sys.exit(0)

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
        #ifdef FILTER_PID
        if (bpf_get_current_pid_tgid() >> 32 != FILTER_PID)
            return 0;
        #endif

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
        #ifdef FILTER_PID
        if (bpf_get_current_pid_tgid() >> 32 != FILTER_PID)
            return 0;
        #endif
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

if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.latency:
    text = "#define LATENCY\n" + text
if args.process:
    text = "#define BY_PROCESS\n" + text
if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

def print_stats():
    if args.latency:
        print_latency_stats()
    else:
        print_count_stats()

agg_colname = "PID    COMM" if args.process else "SYSCALL"
time_colname = "TIME (ms)" if args.milliseconds else "TIME (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "rb").read().strip()
    except Exception:
        return b"[unknown]"

def agg_colval(key):
    if args.process:
        return b"%-6d %-15s" % (key.value, comm_for_pid(key.value))
    else:
        return syscall_name(key.value)

def print_count_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s" % (agg_colname, "COUNT"))
    for k, v in sorted(data.items(), key=lambda kv: -kv[1].value)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb(b"%-22s %8d" % (agg_colval(k), v.value))
    print("")
    data.clear()

def print_latency_stats():
    data = bpf["data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-22s %8s %16s" % (agg_colname, "COUNT", time_colname))
    for k, v in sorted(data.items(),
                       key=lambda kv: -kv[1].total_ns)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        printb((b"%-22s %8d " + (b"%16.6f" if args.milliseconds else b"%16.3f")) %
               (agg_colval(k), v.count,
                v.total_ns / (1e6 if args.milliseconds else 1e3)))
    print("")
    data.clear()

print("Tracing %ssyscalls, printing top %d... Ctrl+C to quit." %
      ("failed " if args.failures else "", args.top))
exiting = 0 if args.interval else 1
seconds = 0
while True:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print_stats()

    if exiting:
        print("Detaching...")
        exit()