# bpf-examples

After cloned the repo, update the submodules first.
```sh
git submodule update --init
```

## libbpf
Build and install libbpf

```sh
cd libbpf/src
make
make install
```

libelf/libz, internal dependencies of libbpf, must be also installed.

## bpftool
Build and install bpftool

```sh
cd bpftool
git submodule update --init
cd src
make
```

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
