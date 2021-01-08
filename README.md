# bpf-examples

## libbpf

libbpf is a library for ease development and loading BPF programs. It is part of
kernel tree under tools/lib/bpf, but Facebook engineers maintain a mirror on
Github: https://github.com/libbpf/libbpf.

It is added as a submodule via:
#+begin_example
git submodule add https://github.com/libbpf/libbpf/ libbpf
#+end_example

After clone this repo, you need to run the command:

#+begin_example
git submodule update --init
#+end_example

## Dependencies
Main dependencies are:
- libbpf
- llvm
- clang
- libelf


## bpftool

bpftool is part of Linux kernel tree under tools/bpf/bpftool. Linux distribution might
ship the tool as a package, but it might be not the latest. A copy of the tool from
BCC repo is stored in bin directory.


