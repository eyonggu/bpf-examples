# bpf-examples

## libbpf

libbpf is a library for ease development and loading BPF programs. It is part of
kernel tree under tools/lib/bpf, but Facebook engineers maintain a mirror on
Github: https://github.com/libbpf/libbpf.

It is added as a submodule via:

```console
git submodule add https://github.com/libbpf/libbpf/ libbpf
```

After clone this repo, you need to run the command:

```console
git submodule update --init
```

Refer to libbpf README file for how to compile and install

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

More usages, please look at Quentin Monnet's twitter: https://twitter.com/qeole/status/1101450782841466880

Some examples:

```console
bpftool prog show
bpftool prog load foo.o /sys/fs/bpf/bar
bpftool prog dump xlated id 40

bpftool map show
bpftool map getnext id 27
bpftool map getnext id 27 key 1 0 0 10
bpftool map lookup id 182 key 0x01 0x00 0x00 0x00
bpftool map update id 7 key 3 0 0 0 value 1 1 168 192
bpftool map create /sys/fs/bpf/stats_map type array key 4 value 32 entries 8 name stats_map

bpftool net show [dev <iface>]  #list program attached to TC or XDP hooks

bpftool prog pin id 27 /sys/fs/bpf/foo_prog

bpftool batch file <file>
```

## trouble-shooting

Enable bpf program stats:

```console
sysctl -w kernel.bpf_stats_enabled=1
bpftool prog show id <id>

```
