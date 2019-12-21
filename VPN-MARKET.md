# TonGate

Proxy/tunnel network traffic through some TON network member. Handle DNS resolution in .ton zone.

## Overview of tunneling software/services

### Virtual interface (TUN) based software

#### OpenVPN

* OpenVPN cli
* official OpenVPN Connect Client
* Tunnelblick (macos)
* Viscosity

#### WireGuard

* Wireguard official
    Mac gui -- userspace tunnel creation via NETunnelProvider
    Win gui -- uses own wintun driver
    Linux cli -- uses kernel module implementation
    Anroid app
    iOS app
    GPLv2 for linux kernel module, MIT for frontends and other stuff

    All backend/frontend/protocols are mostly done by Jason A. Donenfeld (www.zx2c4.com)

* TunSafe
    Mac and Linux cli (requires root, ioctl-based tunnel creation)
    Win gui
    iOS app
    Anroid app
    AGPL

    tunsafe.com provides free 1 month servers, and shaped 1Gb/day afterward
    iOS app is not available in Russian appstore

* BoringTun
    rust version of protocol

#### IPSec

### SOCKS based software

+ Tunneling will not disappear on reconnect -- that's quite a big security risk with TUN-based stuff.
+ Can be done on per-app basis (even on per-website basis) or for a whole system
+ No need to edit nameserver and roung tables
+ 
+ shadowsocks as a brand seem to be popular in some communities. Association with shadowsocks may bring some new users.

- some apps may not support socks (however most browsers/torrents/etc do support it)
