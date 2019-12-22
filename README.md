# tongate

Proof-of-concept market of entry points to the TON network.

`tongate` client allows to find `tongate` servers by looking up members of 'ProxyOffers' overlay network in TON DHT.
Once such server is found client establishes encrypted connection to that server, starts local SOCKS5 proxy and pass
traffic to that server. When destination is ordinary domain or ip address server acts a proxy.
When destination is a domain name with `.ton` TLD then server will transaparenty resolve it to the ADNL address, and then to IP adress using DHT.

