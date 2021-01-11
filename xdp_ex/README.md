# XDP Example

## Manually load/unload xdp program using ip tool
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose
sudo ip link set dev lo xdp off

## use userspace test program to load/unload
sudo ./xdp_test -d lo -f xdp_drop_world_kern.o
ping 127.0.0.1
sudo ./xdp_test -d lo -u

## show xdp program on the link
ip link show dev lo

bpftool net list dev lo

## detach
sudo bpftool net detach xdp dev lo
(prog is destroyed after detach for no reference on it)


## Test xdp_drop_udp
sudo hping3 127.0.0.1 -2
sudo ./xdp_test -d lo -f xdp_drop_udp_kern.o
sudo hping3 127.0.0.1 -2
sudo ./xdp_test -d lo -u

