#Hello BPF

This is a bpf program following examples in kernel samples/bpf/,
but it can be built out of kernel tree

##Precondition
libbpf must be present.

To build and install libbpf
- git clone https://github.com/libbpf/libbpf
- cd libbpf/src
- make
- make install

libelf/libz, internal dependencies of libbpf, must be also present.


##Compile
make

##Run
sudo ./hello_bpf &

Execute a shell command to see the print, e.g.  ls

