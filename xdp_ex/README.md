# XDP Example

## Manually load/unload xdp program using ip tool
```console
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose
sudo ip link set dev lo xdp off
```

## use userspace test program to load/unload
```console
sudo ./xdp_loader -d lo -f xdp_drop_world_kern.o
ping 127.0.0.1
sudo ./xdp_loader -d lo -u
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

sudo ./xdp_loader -d lo -f xdp_drop_udp_kern.o

sudo hping3 127.0.0.1 -2

sudo ./xdp_loader -d lo -u
```

## Test xdp_stat

One step: <br/>
```console
sudo ./xdp_stats -d lo -f xdp_stats_kern.o &
```

Two steps: <br/>
```console
sudo ./xdp_loader -d lo -f xdp_stats_kern.o
sduo ./xdp_stats -d lo -s &
```

## Test paacket parse

Best to setup test environment using the script below: <br/>
https://github.com/xdp-project/xdp-tutorial/tree/master/testenv

```console
sudo ./xdp_loader -d test -f xdp_packet_parsing_kern.o

t exec -- ping6 fc00:dead:cafe:1::1
```



