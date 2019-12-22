# tongate

Market of entry points to the TON network.

`tongate` client allows to find `tongate` servers by looking up members of 'ProxyOffers' overlay network in TON DHT.
Once such server is found client establishes encrypted connection to that server, starts local SOCKS5 proxy and pass
traffic to that server. When destination is ordinary domain or ip address server acts as a proxy.
When destination is a domain name with `.ton` TLD then server will transaparenty resolve it to the ADNL address, and then to IP adress using DHT. 

## Current state

- [x] Overlay network to discover tongate servers
- [x] Encrypted communications betwen client and server (kind of ADNL-over-TCP, works when client is behind NAT)
- [ ] SOCKS5 (work-in-progress)
- [ ] Tun interface (work-in-progress)
- [ ] `*.ton` domain resolution
- [ ] Payment channel between client and server
- [ ] Local http server in client with stats and payment QR-code generator
- [ ] Tray gui for starting/stopping client

## Building

To build run following commands:
```sh
> git clone --recursive https://github.com/kelvich/tongate
> cd tongate && mkdir build && cd build
> cmake ../
> make -j 6
```
After that build directory will contain `client` and `tongate` binaries.

## Running server

```sh
> ./tongate -D dbs C ton-global.config.json -a IP:PORT -s -v 2
```
Where `IP:PORT` is advertised adress of that server and should be externally accessible.

## Discovering server

To find a node to connect run following:
```sh
>  ./tongate -D dbs_discovery -a IP:PORT -v 2 -L
```
Where `IP:PORT` should be externally accessible. If you are behind the NAT you may find out your external address and sent port to some random number. Usually NAT prepserves sending UDP port (if it was not already occupied) and you will be able to get DHT responses back.

## Running client

To connect to the selected server run:
```sh
> ./client -v 4 -c SERVER_IP:PORT -p SERVER_PUBKEY
```
That will also start local SOCKS5 server on port 5555 (which is not yet working, but just emits some stuff in log when somebody connects to it).


