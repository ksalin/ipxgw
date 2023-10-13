# DOSBox IPXNET to real IPX network gateway

This is a small program which contains parts from DOSBox sources which
enables it to act as a IPXNET server where DOSBox(es) can connect to.
Besides being a dedicated server it also mirrors the IPX packets between
a real physical ethernet network where real DOS computers can be
connected to. This allows playing IPX games between real computers on
one end and DOSBox emulators at another end.

## Compiling

Ipxgw requires libpcap, SDL 1.2, and SDL_net libraries with headers
installed besides g++ and standard C headers to compile. If you are
running Debian or Ubuntu, install requirements by running:

	sudo apt install build-essential libpcap-dev libsdl-net1.2-dev 

Then just:

	make
	
There is also autotools support added.

## Usage

If you are running "modern" IPX network at your LAN, then you just
need to define the interface where your IPX network is. In case the
interface is `eth0`, run:

	ipxgw eth0

Because low level packet capture is required, superuser privileges are
normally needed. Use `sudo` if needed.

UDP port 213 is used by default and can be changed using `-p` option.

If your computers in real network are running Novell raw IEEE 802.3
IPX stack instead of Logical Link Control (IEEE 802.2), then you need
to change the frame structure with Ipxgw `-r` switch. For example:

	ipxgw -r eth0

If your computers in real network are running Ethernet II
IPX stack instead of IEEE 802.x, then you need
to change the frame structure with Ipxgw `-e` switch. For example:

	ipxgw -e eth0

Ethernet II also adds dynamic IPX node number allocation on the host
network, to prevent conflicting IPX node numbers.

More information at [Wikipedia](https://en.wikipedia.org/wiki/Ethernet_frame#Novell_raw_IEEE_802.3).

To see other available parameters, use -h for help.

## DOSBox configuration

More comprehensively documented in
[DOSBox Wiki](https://www.dosbox.com/wiki/Connectivity#IPX_emulation).
This is a short summary:

First, enable IPX. Ensure you have the following in DOSBox
configuration:

```ini
[ipx]
ipx=true
```

Then run the following on DOSBox where *10.0.0.1* and *213* are the IP
address of the machine running Ipxgw and Ipxgw port number:

```bat
IPXNET CONNECT 10.0.0.1 213
```

## Background

We were lazy and so config.h has some hard-coded values. They should
suffice for most users and the code compiles and works at least with
both AMD64 Linux system and 32-bit Raspberry Pi.

This is untested with combination of multiple real DOS computers, but it
works with at least one. Problem might also be if you use a switch and not
a simple old hub with those multiple computers because some packets might
not be visible to the gateway and therefore not sent to DOSBox(es).

You might ask, why do this? Well, there exists NE2000 driver for DOSBox
but that does not work over the Internet - it allows only a local DOS 
computer to talk with a local DOSBox. This is the only way to allow
remote DOSBox people to connect with your real DOS computer to play IPX
games, as long as you can run the server.

The code could be improved a lot as it was just quickly hacked together
and then made to work with help of some wireshark debugging. Feel free
to improve it as the license allows.

## License

Copyright (C) 2015, 2023 Kati Salin
Copyright (C) 2020 Joel Lehtonen

Licenced under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

Contains parts from DOSBox source code by The DOSBox Team, under GPLv2
