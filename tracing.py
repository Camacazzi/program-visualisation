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
import prctl
import operator
import pwd
from datetime import datetime
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

prctl.set_child_subreaper(1)

#syscall = []
#method = []
#method_merged = []
#x_children = []

timeout = 500



#123
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

def retrieve_pub_functions(binary):
    symbols = []
    with open(binary, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return -1

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        # get .debug_pubtypes section.
        pubnames = dwarfinfo.get_pubnames()
        if pubnames is None:
            print('ERROR: No .debug_pubnames section found in ELF.')
            return -1
        else:
            print('%d entries found in .debug_pubnames' % len(pubnames))
        
            # dump all entries in .debug_pubnames section.
            print('Dumping .debug_pubnames table ...')
            print('-' * 66)
            print('%50s%8s%8s' % ('Symbol', 'CU_OFS', 'DIE_OFS'))
            print('-' * 66)
            for (name, entry) in pubnames.items():
                symbols.append(name)
                print('%50s%8d%8d' % (name, entry.cu_ofs, entry.die_ofs))
                #print(entry)
            print('-' * 66)

            print(symbols)

            return symbols

def print_event_perf(cpu, data, size):
    global start
    sys_event = bpf["events"].event(data)
    if(sys_event.identifier == 1):
        #printing exit system calls
        #l = (1, sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys).decode('utf-8'),sys_event.ex_sys, sys_event.ex_ret)
        l = (1, sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys).decode('utf-8'),sys_event.ex_sys, sys_event.testret)
        syscall.append(l)
        print("testret: %-20d" % (sys_event.testret))
        #print(syscall)
        #print("exit: %-20d %22s %12d %20s %15d %15d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32).decode('utf-8'), sys_event.ex_pid32, syscall_name(sys_event.ex_sys).decode('utf-8'),sys_event.ex_sys, sys_event.ex_ret))
    elif(sys_event.identifier == 0):
        #printing enter system calls
        l = (0, sys_event.time, comm_for_pid(sys_event.ent_pid32), sys_event.ent_pid32, syscall_name(sys_event.ent_sys).decode('utf-8'), sys_event.ent_sys)
        syscall.append(l)
        
        #print("enter: %-20d %22s %12d %20s %15d" % (sys_event.time, comm_for_pid(sys_event.ent_pid32).decode('utf-8'), sys_event.ent_pid32, syscall_name(sys_event.ent_sys).decode('utf-8'), sys_event.ent_sys))
    elif(sys_event.identifier == 2):
        #printing method enter calls
        l = (2, sys_event.time, sys_event.ent_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ent_pid32).decode('utf-8'))
        method.append(l)
        print("method ent: %-20d %12d %8d %15s" % (sys_event.time, sys_event.ent_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ent_pid32).decode('utf-8')))
    elif(sys_event.identifier == 3):
        #printing method exit calls
        l = (3, sys_event.time, sys_event.ex_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ex_pid32).decode('utf-8'), sys_event.ex_ret)
        method.append(l)
        print("method ex: %-20d %12d %8d %15s %12d" % (sys_event.time, sys_event.ex_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ex_pid32).decode('utf-8'), sys_event.ex_ret))
    elif(sys_event.identifier == 4):
        #process has spawned
        x_children.append(sys_event.ent_pid32)


def organise(syscall_list, method_list, parent, x_children):
    #take method data
    #split up into pids, order by time
    #work outwards from the middle finding matching pairs, after going through them all use a sorting algorithm
    #combine the syscall lists
    #output dictionary of pid's as keys, containing 2 arrays each, one for methods, one for syscalls
    merged = {parent: [[], []]}
    for i in x_children:
        merged[i] = [[], []]
    method_list.sort(key = operator.itemgetter(2,1))
    #print(method)
    #loop through until pid changes
    #find last occurence of a method enter occurring for that pid, that and the subsequent method exit are the same, do eqn and do calcs, store in dic, then del from array
    #search index up for next occurence of 2, repeat process until index of 0 reached
    # ident, sys_event.time, sys_event.ex_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ex_pid32), sys_event.ex_ret)
    #print(syscall_list)
    #print(method_list)
    curr_pid = method_list[0][2] 
    i = 1
    last_ent_index = 0
    method_temp = []
    #print("method_list len: " + str(len(method_list)))
    while len(method_list) > 0:
        #print("i: " + str(i))
        if(i < len(method_list) and method_list[i][2] == curr_pid):
            #print(("method pid: %d curr_pid %d") % (method_list[i][2], curr_pid))
            #keep searching for end of pid
            if(method_list[i][0] == 2):
                #we found a method enter
                last_ent_index = i
            i = i + 1
            continue
        else:
            #print("entered organise else:")
            #print("last_ent_index = " + str(last_ent_index))
            #do the calcs, delete from array
            #what to do if things are mismatched/program ended early? what should of happened is there will be an enter with no subsequent exit
            #this can happen one of two ways, function starts, and has no other functions inside it to run, so it exits, but it doesn't exit. 
            #This would have an ent be at the end of the list of methods. Check for if the next ex is from same pid/actually exists
            #if it has functions inside it to run, but never finished itself, eventually we will reach this stage too.
            #solution: Check for if the next ex is from same pid/actually exists, if this happens it will be the last entry from the pid, and it will be an enter
            #turns out we can have exits without a subsequent enter
            method_temp.append((method_list[last_ent_index][1], method_list[last_ent_index + 1][1]-method_list[last_ent_index][1], method_list[last_ent_index][2], method_list[last_ent_index][4], method_list[last_ent_index+1][5]))
            #method_temp.append((method_list[last_ent_index + 1][1]-method_list[last_ent_index][1], method_list[last_ent_index][2]))

            #print("method_temp 1: ")
            #print(method_temp)
            del method_list[last_ent_index]
            #del method_list[last_ent_index + 1]
            del method_list[last_ent_index]
            #print("method_list 1: ")
            #print(method_list)
            #shift up i until we get another 2 value, keep going until we hit 0
            last_ent_index = last_ent_index -1
            while last_ent_index > -1:
                if(method_list[last_ent_index][0] == 2):
                    #print("last_ent_index in second loop: "+ str(last_ent_index))
                    method_temp.append((method_list[last_ent_index][1], method_list[last_ent_index+ 1][1]-method_list[last_ent_index][1], method_list[last_ent_index][2], method_list[last_ent_index][4], method_list[last_ent_index+1][5]))
                    del method_list[last_ent_index]
                    #del method_list[last_ent_index + 1]
                    del method_list[last_ent_index]
                last_ent_index = last_ent_index - 1
            #print("method_temp 2: ")
            #print(method_temp)
            #print("method_list 2: ")
            #print(method_list)
            #by this point we should of cleared out all of the pid from the start of the array
            #however if we need to check if we have an exit, with no enter, if so, maybe through it out? Maybe not.
            if(method_list[last_ent_index + 1][0] == 3):
                method_temp.append((method_list[last_ent_index+1][1],-1, method_list[last_ent_index+1][2], method_list[last_ent_index+1][4], method_list[last_ent_index+1][5]))
                del method_list[last_ent_index]
            if(len(method_list) > 0):
                #if it isn't 0, assume the loop will end
                i = 0
                curr_pid = method_list[0][2]
    #now to load them into the merged dictionary
    method_temp.sort(key = operator.itemgetter(0))
    #print(method_temp)
    for i in range(len(method_temp)):
        merged[method_temp[i][2]][0].append(method_temp[i])   
    #print(merged)
    syscall_temp = []       
    #now for the syscall stuffp
    syscall_list.sort(key = operator.itemgetter(3,1))
    i = 0
    j = 0
    #print(syscall_list)
    #(1, sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret)
    exec_reached = 0
    #right now I'm assuming we should be looking at an enter
    while i < len(syscall_list):
        #don't include info from before execve is called, strip it out
        try:
            if syscall_list[i][5] == 59:
                exec_reached = 1
                #print("i val first if: %d" % (i))
            if exec_reached == 0:
                #print("syscall: %s" % (syscall_list[i][4]))
                #print("i val second if: %d" % (i))
                i = i + 1
                continue
            else:
                if(syscall_list[i][5] == syscall_list[i+1][5]):
                    #all is good in the world, I think
                    #print("i val 3rd if: %d" % (i))
                    merged[syscall_list[i][3]][1].append((syscall_list[i][1], syscall_list[i+ 1][1]-syscall_list[i][1], syscall_list[i][3], syscall_list[i][4], syscall_list[i+1][6]))
                else:
                    #print("i val 2nd else if: %d" % (i))
                    #("i: %d i+1: %d" % (syscall_list[i][5], syscall_list[i+1][5]))
                    #fire and chaos, a process may not of exited correctly, leaving a hanging syscall, or exit_group was called
                    #append this lone strangler, having duration be -1, assuming it's an enter
                    #advance the ticker by 1
                    merged[syscall_list[i][3]][1].append((syscall_list[i][1], -1, syscall_list[i][3], syscall_list[i][4]))
                    i = i + 1
                    continue
                i = i + 2
        except IndexError: 
            #assume there is a lone straggler at the end when trying to access i + 1, loop will likely end now
            merged[syscall_list[i][3]][1].append((syscall_list[i][1], -1, syscall_list[i][3], syscall_list[i][4]))
            i = i + 1


    #print(merged)
    return merged

def save_data(data, parent, x_children):
    time = datetime.now()
    file_string = time.strftime("Tracing_data_%d.%m.%Y_%H:%M:%S.trc")
    #print(file_string)
    f = open(file_string, 'w')
    f.write("D1 " + str(parent) + "\n")
    f.write("D2 " + str(x_children) + "\n")
    f.write(";" + "\n" + "M" + "\n")
    
    for i in data[parent][0]:
        f.write(str(i) + "\n")
    f.write(";" + "\n" + "S" + "\n")
    for i in data[parent][1]:
        f.write(str(i) + "\n")
    for i in x_children:
        f.write(";" + "\n" + "M" + "\n")
        for j in data[i][0]:
            f.write(str(j) + "\n")
        f.write(";" + "\n" + "S" + "\n")
        for j in data[i][1]:
            f.write(str(j) + "\n")
    #idea: add a splitter to each section, with an identifier at the top of each section (method/syscall), and then split on that
    #then use splitter again to split into individual items, and go through previous process to put them into individual items
    
def load_data(file):
    n = 0
    x_children = []
    temp_str = ""
    temp_tpl = ()
    data = 0
    f = open(file, 'r')
    """for i in f:
        if(i[0] == 'D'):
            temp_str = i.split(" ")
            if(temp_str[0] == "D1"):
                n = int(temp_str[1])
            elif(temp_str[0] == "D2"):
                x_children = temp_str[1]
            continue
        temp_str = i[1:len(i)-2].split(", ")
        if len(temp_str) == 5:
            temp_tpl = (int(temp_str[0]), int(temp_str[1]), int(temp_str[2]), temp_str[3][1:len(i)-1], int(temp_str[4]))
        elif len(temp_str) == 4:
            temp_tpl = (int(temp_str[0]), int(temp_str[1]), int(temp_str[2]), temp_str[3][1:len(i)-1])
        data[temp_tpl[2]] = temp_tpl
    return (data, n, x_children)"""
    f = f.read()
    main_split = f.split(";")
    temp_split = main_split[0].split("\n")
    if(temp_split[0][0:2] == "D1"):
        data_split = temp_split[0].split(" ")
        n = int(data_split[1])
        data_split2 = temp_split[1].split(" ")
        x_children = data_split2[1]
    else:
        #something gone wrong
        return -1
    x_children = x_children[1:len(x_children)-1].split(",")
    for i in range(len(x_children)):
        x_children[i] = int(x_children[i])
    #create spots for all children
    data = {n: [[], []]}
    print("x_child: "+ str(x_children))
    for i in x_children:
        data[i] = [[], []]
    #now we can loop through the rest of the data

    #NEED TO ADD THE BIT TO CHECK IF METHOD OR SYSCALL!!!!!
    #m_or_s is the var that says if the block is a method block or syscall block
    m_or_s = 0
    #print("main split: " + str(main_split))
    for i in range(1, len(main_split)):
        temp_split = main_split[i].split("\n")
        for j in temp_split:
            if(j == 'M'):
                m_or_s = 0
                continue
            elif(j == 'S'):
                m_or_s = 1
                continue
            elif(j == ''):
                continue
            print("j: " + str(j))
            temp_str = j[1:len(j)-1].split(", ")
            print("temp_str: " + str(temp_str))
            if len(temp_str) == 5:
                temp_tpl = (int(temp_str[0]), int(temp_str[1]), int(temp_str[2]), temp_str[3][1:len(temp_str[3])-1], int(temp_str[4]))
            elif len(temp_str) == 4:
                temp_tpl = (int(temp_str[0]), int(temp_str[1]), int(temp_str[2]), temp_str[3][1:len(temp_str[3])-1])
            print("tuple: "+str(temp_tpl))
            data[temp_tpl[2]][m_or_s].append(temp_tpl)
    return (data, n, x_children)

        



#def main():     
def main(program_path, user):
    global syscall
    global method
    global method_merged
    global x_children
    print("setting stores to empty")
    syscall = []
    method = []
    method_merged = []
    x_children = []
    counter = 0

    #prctl.set_child_subreaper(1)

    #program = "testfork"
    #exec_program = "./" + program
    exec_program = program_path
    if(user!="Root"):
        try:
            uid = pwd.getpwnam(user).pw_uid
            print("uid: " + str(uid) + "\n")
        except Exception as e:
            if(e == errno.ESRCH):
                print("User not found")
                return -1
            else:
                print("Unknown error")
                return -1
    else:
        print("running in root")
        print(os.getuid())
    

    n = os.fork()
    if n == 0: #child
        #switching to given user if not root
        if(user!="Root"):
            print("switching uid")
            os.setuid(uid)
        print(os.getuid())
        print("child waiting for signal")
        #signal.pause()
        signal.signal(signal.SIGUSR1, signal_ignore)
        print("signal receieved")
        sleep(0.5)
        print("PID of child is: " + str(os.getpid()))
        
        os.execl(exec_program, *sys.argv)
        #run program
        #program end
        os._exit(0)
    else: #parent
        #define the bpf program to run
        text = """
        #include <uapi/linux/ptrace.h>
        //#include <stdio.h>

        struct data_t{
            u64 ent_pid_tgid; // process id
            u32 ent_pid32; //pid after the 32 bit shift
            u32 ent_sys; // syscall
            u64 ex_pid_tgid; // process id
            u32 ex_pid32; //pid after the 32 bit shift
            u32 ex_sys; // syscall
            u32 ex_ret; //return arguments
            //u64 ex_ret;
        };

        //identifier: 0 = system call enter, 1 = system call exit, 2 = method enter, 3 = method exit, 4 = child notification
        struct data_t_perf{
            u64 time;
            u32 identifier; //if 4, new child has spawned, its pid will be in ent_pid32, add it to the children array and check for when it exits
            u64 ent_pid_tgid; // process id
            u32 ent_pid32; //pid after the 32 bit shift
            u32 ent_sys; // syscall
            u64 ex_pid_tgid; // process id
            u32 ex_pid32; //pid after the 32 bit shift
            u32 ex_sys; // syscall
            u32 ex_ret; //return arguments
            //u64 ex_ret;
            u64 ip; //instruction pointer
            s32 testret;
        };
        
        struct data_method{
            //0 is method enter, 1 is method exit. May refactor previous syscall code to utilise this.
            u32 identifier;
            u64 pid_tgid;
            u32 pid32;
            u64 ip;
            u64 rc;
        };

        BPF_HASH(data, u64, struct data_t, 500000);
        //BPF_HASH(data_exit_hash, u64, struct data_exit, 500000);
        BPF_HASH(children, u32, u32);

        BPF_HASH(method_ent, u64, struct data_method);
        BPF_HASH(method_ex, u64, struct data_method);

        BPF_PERF_OUTPUT(events);
        //BPF_PERF_OUTPUT(events)

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
                val_perf.identifier = 0;
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
            u32 four = 4;
            u32 clone = 56;
            if (current_pid == FILTER_PID){
                if(args->id == clone){
                    u32 ret = args->ret;
                    children.lookup_or_try_init(&ret, &one);
                    struct data_t_perf val_perf_child = {};
                    val_perf_child.ent_pid32 = ret;
                    val_perf_child.identifier = four;
                    events.perf_submit(args, &val_perf_child, sizeof(val_perf_child));
                }
            }
            else{
                u32 *check = children.lookup(&current_pid);
                    if(check){
                        if(args->id == clone){
                            u32 ret = args->ret;
                            children.lookup_or_try_init(&ret, &one);
                        }
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
                val_perf.identifier = one;
                val_perf.ent_pid_tgid = 0;
                val_perf.ent_pid32 = 0;
                val_perf.ent_sys = 0;
                val_perf.ex_pid_tgid = val->ex_pid_tgid;
                val_perf.ex_pid32 = val->ex_pid32;
                val_perf.ex_sys = val->ex_sys;
                val_perf.ex_ret = val->ex_ret;
                val_perf.ip = 0;
                //bpf_trace_printk(\"%d\", args->id);
                val_perf.testret = args->ret;
                events.perf_submit(args, &val_perf, sizeof(val_perf));
            }
            return 0;
        }

        int method_enter(struct pt_regs *ctx){
            u64 t = bpf_ktime_get_ns();
            u64 pid = bpf_get_current_pid_tgid();
            u32 two = 2;

            struct data_method *val, zero={};
            //struct data_method_perf val_perf = {};
            struct data_t_perf val_perf = {};
            val = method_ent.lookup_or_try_init(&t, &zero);
            if(val){
                val->pid_tgid = pid;
                val->pid32 = val->pid_tgid >> 32;
                val->ip = PT_REGS_IP(ctx);

                val_perf.time = t;
                val_perf.identifier = two;
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

        int method_exit(struct pt_regs *ctx){
            u64 t = bpf_ktime_get_ns();
            u64 pid = bpf_get_current_pid_tgid();
            u32 three = 3;

            struct data_method *val, zero={};
            //struct data_method_perf val_perf = {};
            struct data_t_perf val_perf = {};
            val = method_ex.lookup_or_try_init(&t, &zero);
            if(val){
                val->pid_tgid = pid;
                val->pid32 = val->pid_tgid >> 32;
                val->ip = PT_REGS_IP(ctx);
                val->rc = PT_REGS_RC(ctx);

                val_perf.time = t;
                val_perf.identifier = three;
                val_perf.ex_pid_tgid = val->pid_tgid;
                val_perf.ex_pid32 = val->pid32;
                val_perf.ip = val->ip;
                val_perf.ex_ret = val->rc;

                val_perf.ent_sys = 0;
                val_perf.ent_pid_tgid = 0;
                val_perf.ent_pid32 = 0;
                val_perf.ent_sys = 0;

                events.perf_submit(ctx, &val_perf, sizeof(val_perf));
            }
            return 0;
        }
        """
        #PID filter
        text = ("#define FILTER_PID %d\n" % n) + text

        #set variables to capture data
        """syscall = []
        method = []
        method_merged = []
        x_children = []"""
        #filename = program
        #symbols = []

        #retrieve symbol data (if we intend to)
        print('Processing file:', program_path)
        symbols = retrieve_pub_functions(program_path)
        if(symbols == -1):
            print("No debug info available, yet the program has been told that there is. Exiting\n")

        #begin tracing
        global bpf
        bpf = BPF(text=text) 

        #attach uprobes and uretprobes to all symbols found
        for methods in symbols:
            bpf.attach_uprobe(name=exec_program, sym=methods, fn_name="method_enter")
            bpf.attach_uretprobe(name=exec_program, sym=methods, fn_name="method_exit")
        
        #bpf.attach_uprobe(name=exec_program, sym=fprintf, fn_name="method_enter")
        #bpf.attach_uretprobe(name=exec_program, sym=fprintf, fn_name="method_exit")

        #tell child to start tracing
        #need to change from sigusr1, it can get thrown out
        os.kill(n, signal.SIGUSR1)

        
        bpf["events"].open_perf_buffer(print_event_perf)
        while 1:
            try:
                bpf.perf_buffer_poll(timeout=5)
                os.waitpid(-1, os.WNOHANG)
                """if(counter < timeout):
                    counter = counter + 1
                    print("Counter: "+ str(counter) + "\n")
                else:
                    print("Timeout reached")
                    result = organise(syscall, method, n, x_children)
                    return result, n, x_children
                    exit()"""
            except KeyboardInterrupt:
                print("KB Interrupt: Warning: tracing may not have properly completed")
                result = organise(syscall, method, n, x_children)
                #return result, n, x_children
                return (result, n, x_children)
                exit()
            except OSError:
                result = organise(syscall, method, n, x_children)
                print("Program has shut down, or can no longer be found. Tracing is ending.")
                save_data(result, n, x_children)
                #send to main program
                #return result, n, x_children
                return (result, n, x_children)
                #break
                exit()
#main()
                
            




