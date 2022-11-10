# XDP Example

* **xdp_drop_world**: drop all packets
* **xdp_drop_udp**: drop udp packets
* **xdp_xdp_stat**: packet statistics with map
* **xdp_packert_parsing**: parse packet header, drop every second icmp packet
* **xdp_redirect**:

## load program
* ip link command

```console
sudo ip link set dev lo xdp obj xdp-drop-world.o sec xdp verbose
sudo ip link set dev lo xdp off
```

* xdp_loader

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

## Test packet parsing

Best to setup test environment using the script below: <br/>
https://github.com/xdp-project/xdp-tutorial/tree/master/testenv

```console
sudo ./xdp_loader -d test -f xdp_packet_parsing_kern.o

t exec -- ping6 fc00:dead:cafe:1::1
```

## Test redirect

```console
t exec -n test -- ./xdp_loader -d veth0 -f xdp_redirect_kern.o --progsec xdp_pass
sudo ./xdp_loader -d test -f xdp_redirect_kern.o -s xdp_icmp_echo -p

t ping
sudo ./xdp_stats -d test
```

```console

t setup -n left
t setup -n right

t exec -n left -- ip link
t exec -n left -- ip addr
# replace dst[] and ifindex in "xdp_redirect" function

t exec -n left -- ./xdp_loader -d veth0 -f xdp_redirect_kern.o --progsec xdp_pass
sudo ./xdp_loader -d right -f xdp_redirect_kern.o -s xdp_redirect -p
t exec -n right - ping <left inner IP>

# check packet received on left inner interface by "ip -s link" or "tcpdump"

```



