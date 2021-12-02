# traceroute

An asynchronous traceroute toy implementation written in Rust.

# How it works

**traceroute** sends UDP datagrams and relies on the hosts along the path to send an ICMP packet back when TTL drops to 0. Starting with TTL == 1, it gradually increments it until the destination host is reached.

Status: WIP