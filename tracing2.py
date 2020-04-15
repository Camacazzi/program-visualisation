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
import prctl
import operator
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
    for i in range(len(method_temp)):
        merged[method_temp[i][2]][0].append(method_temp[i])   
    #print(merged)
    syscall_temp = []       
    #now for the syscall stuffp
    syscall_list.sort(key = operator.itemgetter(3,1))
    i = 0
    j = 0
    print(syscall_list)
    #(1, sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret)
    exec_reached = 0
    #right now I'm assuming we should be looking at an enter
    while i < len(syscall_list):
        #don't include info from before execve is called, strip it out
        try:
            if syscall_list[i][5] == 59:
                exec_reached = 1
                print("i val first if: %d" % (i))
            if exec_reached == 0:
                print("syscall: %s" % (syscall_list[i][4]))
                print("i val second if: %d" % (i))
                i = i + 1
                continue
            else:
                if(syscall_list[i][5] == syscall_list[i+1][5]):
                    #all is good in the world, I think
                    print("i val 3rd if: %d" % (i))
                    merged[syscall_list[i][3]][1].append((syscall_list[i][1], syscall_list[i+ 1][1]-syscall_list[i][1], syscall_list[i][3], syscall_list[i][4], syscall_list[i+1][6]))
                else:
                    print("i val 2nd else if: %d" % (i))
                    print("i: %d i+1: %d" % (syscall_list[i][5], syscall_list[i+1][5]))
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


    print(merged)
    return merged


            
        



program = "testfork"
exec_program = "./" + program


n = os.fork()
if n == 0: #child
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
        u64 ip; //instruction pointer
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
    text = ("#define FILTER_PID %d\n" % n) + text


    #syscall_ent = []
    #syscall_ex = []
    syscall = []
    method = []
    #method_ent = []
    #method_ex = []
    method_merged = []
    x_children = []
    filename = program
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
                symbols.append(name)
                print('%50s%8d%8d' % (name, entry.cu_ofs, entry.die_ofs))
                #print(entry)
            print('-' * 66)

            print(symbols)




    bpf = BPF(text=text)


    for methods in symbols:
        bpf.attach_uprobe(name=exec_program, sym=methods, fn_name="method_enter")
        bpf.attach_uretprobe(name=exec_program, sym=methods, fn_name="method_exit")


    prctl.set_child_subreaper(1)


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

    
    def print_event_perf(cpu, data, size):
        global start
        sys_event = bpf["events"].event(data)
        if(sys_event.identifier == 1):
            #printing exit system calls
            l = (1, sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret)
            syscall.append(l)
            print("exit: %-20d %22s %12d %20s %15d %15d" % (sys_event.time, comm_for_pid(sys_event.ex_pid32), sys_event.ex_pid32, syscall_name(sys_event.ex_sys),sys_event.ex_sys, sys_event.ex_ret))
        elif(sys_event.identifier == 0):
            #printing enter system calls
            l = (0, sys_event.time, comm_for_pid(sys_event.ent_pid32), sys_event.ent_pid32, syscall_name(sys_event.ent_sys), sys_event.ent_sys)
            syscall.append(l)
            print("enter: %-20d %22s %12d %20s %15d" % (sys_event.time, comm_for_pid(sys_event.ent_pid32), sys_event.ent_pid32, syscall_name(sys_event.ent_sys), sys_event.ent_sys))
        elif(sys_event.identifier == 2):
            #printing method enter calls
            l = (2, sys_event.time, sys_event.ent_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ent_pid32))
            method.append(l)
            print("method ent: %-20d %12d %8d %15s" % (sys_event.time, sys_event.ent_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ent_pid32)))
        elif(sys_event.identifier == 3):
            #printing method exit calls
            l = (3, sys_event.time, sys_event.ex_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ex_pid32), sys_event.ex_ret)
            method.append(l)
            print("method ex: %-20d %12d %8d %15s %12d" % (sys_event.time, sys_event.ex_pid32, sys_event.ip, bpf.sym(sys_event.ip, sys_event.ex_pid32), sys_event.ex_ret))
        elif(sys_event.identifier == 4):
            #process has spawned
            x_children.append(sys_event.ent_pid32)
    
    bpf["events"].open_perf_buffer(print_event_perf)
    while 1:

        try:
            bpf.perf_buffer_poll()
            os.waitpid(-1, os.WNOHANG)
            #sleep(0.05)
            #print_event_hash()
        except KeyboardInterrupt:
            print("KB Interrupt: Warning: tracing may not have properly completed")
            result = organise(syscall, method, n, x_children)
            exit()
        except OSError:
            #syscalls, methodcalls = organise(syscall_ent, syscall_ex, method, n, x_children)
            result = organise(syscall, method, n, x_children)
            #take method data
            #split up into pids, order by time
            #work outwards from the middle finding matching pairs, after going through them all use a sorting algorithm
            #combine the syscall lists
            print("Program has shut down, or can no longer be found")
            #break
            exit()
        
        
        """except:
            print("original pid is gone")
            k = 0
            while 1:
                if(len(grandchildren) >= 1):
                    gc = grandchildren[k]
                    
                    k = k + 1
                    grandchildren.pop()
                    while 1:
                        try:
                            print("gc: " + str(gc))
                            bpf.perf_buffer_poll()
                            #os.waitpid(gc, os.WNOHANG)
                            os.killpg(gc, 0)
                        except KeyboardInterrupt:
                            print("KB Interrupt: Exiting...")
                            exit()
                        except OSError:
                            break
                else:
                    print(grandchildren)
                    print("Exiting...")
                    exit()"""
                
            




