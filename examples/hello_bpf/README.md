# Hello BPF

A simple BPF program that prints a Hello message in DebugFs/trace when TracePoint `sys_enter_execve` is hit.

## Run
sudo ./hello_bpf &

Execute a shell command to see the print, e.g.  ls

## Check the load program
bpftool prog list

## Check bpf object file
llvm-objdump -D hello.bpf.o
