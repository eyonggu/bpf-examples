# Hello BPF

A simple BPF program that prints a Hello message in DebugFs/trace when TracePoint `sys_enter_execve` is hit.

The loading of program is done via an old `bpf_load` source code copied from kernel, which has been removed
from the kernel source tree since v5.11.

`bpf_load` has dependencies on `libbpf`, which is a submodule in this repo, and built libbpf.a is stored in top `lib` folder.

## Compile

If libbpf is already installed on the host, it can be directly compiled:
```sh
make
```

Otherwise, run following commands to install libbpf header files in `include/bpf` folder.
```sh
cd ../
make libbpf_install
```

## Run
sudo ./hello_bpf &

Execute a shell command to see the print, e.g.  ls

## Check the load program
bpftool prog list

## Check bpf object file
llvm-objdump -D hello_kern.o
