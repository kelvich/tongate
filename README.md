# tongate

Market of entry points to the TON network.

`tongate` client allows to find `tongate` servers by looking up members of 'ProxyOffers' overlay network in TON DHT.
Once such server is found client establishes encrypted connection to that server, starts local SOCKS5 proxy and pass
traffic to that server. When destination is ordinary domain or ip address server acts a proxy.
When destination is a domain name with `.ton` TLD then server will transaparenty resolve it to the ADNL address, and then to IP adress using DHT.

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

## Running client

```sh
> ./client -v 4 -c SERVER_IP:PORT -p SERVER_PUBKEY
```

