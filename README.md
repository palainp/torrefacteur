# torrefacteur

Warning: Not at all executable, this is an early stage :)

[torrefacteur][] is an _ISC-licensed_ Tor client implementation in ocaml.

## Quick test
```bash
sudo ip tuntap add service mode tap
sudo ip addr add 10.0.0.1/24 dev service
sudo ip link set dev service up
sudo sysctl -w net.ipv4.ip_forward=1
mirage configure -t spt && make depend && dune build && \
solo5-spt --net:service=service dist/torrefacteur.spt --ipv4-gateway=10.0.0.1
```

The current state open a connexion to the first onion router, correctly extend the circuit to the second onion router, but fails to extend to the third :(

This unikernel aims to route (NAT) traffic from local connexion to the Tor network.

[torrefacteur]: https://github.com/palainp/torrefacteur
