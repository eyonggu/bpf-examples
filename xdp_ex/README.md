# XDP Example

## Manually load/unload xdp program using ip tool
```console
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose
sudo ip link set dev lo xdp off
```

## use userspace test program to load/unload
```console
sudo ./xdp_simple_load_attach -d lo -f xdp_drop_world_kern.o
ping 127.0.0.1
sudo ./xdp_simple_load_attach -d lo -u
```

## show xdp program on the link
```console
ip link show dev lo

bpftool net list dev lo
```

## detach
```console
sudo bpftool net detach xdp dev lo
```
(prog is destroyed after detach for no reference on it)


## Test xdp_drop_udp
```console
sudo hping3 127.0.0.1 -2

sudo ./xdp_simple_load_attach -d lo -f xdp_drop_udp_kern.o

sudo hping3 127.0.0.1 -2

sudo ./xdp_simple_load_attach -d lo -u
```

## Test xdp_stat

One command with all steps: <br/>
```console
sudo ./xdp_stats -d lo -f xdp_stats_kern.o &
```

Seperate stats from load/attach/pin: <br/>
```console
sudo ./xdp_load_attach_pin -d lo -f xdp_stats_kern.o
sduo ./xdp_stats -d lo -s &
```




