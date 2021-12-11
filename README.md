# traceroute

An asynchronous traceroute toy implementation written in Rust.

# How it works

**traceroute** prints the hosts that packets traverse along the path to the target. At a lower level, it starts from TTL == 1 and sends some UDP datagrams or ICMP echo request packets concurrently, gradually incrementing TTL until they reach the destination host. At each hop, the host decrements the TTL field. When TTL drops to 0, the host sends back an ICMP (time exceeded) message.

Status: WIP
