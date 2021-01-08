# XDP Example

## load xdp program

ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose
