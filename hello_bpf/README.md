# Hello BPF

A simple BPF program that prints a Hello message in DebugFs/trace when TracePoint `sys_enter_execve` is hit.

The loading of program is done via an old `bpf_load` source code copied from kernel, which has been removed
from the kernel source tree since v5.11.

`bpf_load` has dependencies on `libbpf`, which is a submodule in this repo, and built libbpf.a is stored in top `lib` folder.

## Compile

if libbpf is not installed on your host, run following commands to install libbpf header files in `include/bpf` folder.
```sh
make -C ../ libbpf_install
```

There are two ways to build/load bpf programs:
- using `bpf_load` (default)

```sh
make
```
- using `bpftool gen skeleton`

```sh
make USE_BPFTOOL_SKEL=1
```


## Run
sudo ./hello_bpf &

Execute a shell command to see the print, e.g.  ls

## Check the load program
bpftool prog list

## Check bpf object file
llvm-objdump -D hello.bpf.o
