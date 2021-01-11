# Hello BPF

This is a bpf program following examples in kernel samples/bpf/,
but it can be built out of kernel tree.

And the loading of bpf program is done in bpf_load.c file, which is copied from kernel,
but it has been removed since Linux 5.11, because now samples are using skeleton generated
by bpftool.

Note also that loading can be also done via libbpf APIs (see in xdp_ex).

## Precondition
libbpf must be present.

To build and install libbpf
- git clone https://github.com/libbpf/libbpf
- cd libbpf/src
- make
- make install

libelf/libz, internal dependencies of libbpf, must be also installed.


## Compile
make

## Run
sudo ./hello_bpf &

Execute a shell command to see the print, e.g.  ls


## Check bpf object file
llvm-objdump -D hello_kern.o
