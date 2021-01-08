# XDP Example

## load xdp program
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose

## show xdp program on the link
ip link show dev lo

../bin/bpftool net list dev lo

## detach
sudo ../bin/bpftool net detach xdp dev lo
(prog is destroyed after detach for no reference on it)

## removing xdp program
sudo ip link set dev lo xdp off
