# XDP Example

## Manually load/unload xdp program using ip tool
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose

sudo ip link set dev lo xdp off

## use userspace program to load/unload
sudo ./xdp-drop-world_user -d lo -f xdp-drop-world.o

sudo ./xdp-drop-world_user -d lo -u

## show xdp program on the link
ip link show dev lo

../bin/bpftool net list dev lo

## detach
sudo ../bin/bpftool net detach xdp dev lo
(prog is destroyed after detach for no reference on it)

