/*
 *  DOSBox IPXNET to real IPX network gateway
 *  Copyright (C) 2015 Jussi Salin
 *  Contains parts from DOSBox source code by The DOSBox Team, under GPLv2
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "config.h"
#include <unistd.h>
#include <pcap.h>
#include "SDL_net.h"
#include <signal.h>
#include <err.h>

#define ETHER_ADDR_LEN 6				// Ethernet addresses are 6 bytes, for use with pcap
#define ETHER_HEADER_LEN 14				// Ethernet header is two addresses and two bytes size, for use with pcap
#define ENCAPSULE_LEN 3					// Header for encapsulating IPX to Ethernet, for use with pcap
#define SOCKETTABLESIZE 16				// From DosBox
#define CONVIP(hostvar) hostvar & 0xff, (hostvar >> 8) & 0xff, (hostvar >> 16) & 0xff, (hostvar >> 24) & 0xff 	// From DosBox
#define CONVIPX(hostvar) hostvar[0], hostvar[1], hostvar[2], hostvar[3], hostvar[4], hostvar[5]					// From DosBox
#define IPXBUFFERSIZE 1424				// From DosBox
#undef DEBUG							// More output if defined

/*!
 * \brief In Winsock, a socket handle is of type SOCKET; in UN*X, it's
 * a file descriptor, and therefore a signed integer.
 * We define SOCKET to be a signed integer on UN*X, so that it can
 * be used on both platforms. (from pcap/socket.h)
 */
#ifndef SOCKET
#define SOCKET int
#endif

// From DosBox
typedef Bit32u RealPt;

// From DosBox
struct PackedIP {
	Uint32 host;
	Uint16 port;
} GCC_ATTRIBUTE(packed);

// From DosBox
struct nodeType {
	Uint8 node[6];
} GCC_ATTRIBUTE(packed) ;

// From DosBox
struct IPXHeader {
	Uint8 checkSum[2];
	Uint8 length[2];
	Uint8 transControl; // Transport control
	Uint8 pType; // Packet type

	struct transport {
		Uint8 network[4];
		union addrtype {
			nodeType byNode;
			PackedIP byIP ;
		} GCC_ATTRIBUTE(packed) addr;
		Uint8 socket[2];
	} dest, src;
} GCC_ATTRIBUTE(packed);

// Ethernet header for use with pcap
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address
	u_char ether_shost[ETHER_ADDR_LEN]; // Source host address
	u_short ether_type;					// Packet type or length
};

// From DosBox
struct packetBuffer {
	Bit8u buffer[1024];
	Bit16s packetSize;  // Packet size remaining in read
	Bit16s packetRead;  // Bytes read of total packet
	bool inPacket;      // In packet reception flag
	bool connected;		// Connected flag
	bool waitsize;
};

// Hack to allow SDLNet pollable pcap socket. Adapted from
// SDLnetselect.c in SDL_Net
struct Pcap_Socket {
	int ready;
	SOCKET channel;
};

// Some globally shared variables
char errbuf[PCAP_ERRBUF_SIZE];				// Buffer for pcap error messages
pcap_t *handle;								// Handle for pcap
IPaddress ipxServerIp;  					// IPAddress for server's listening port
UDPsocket ipxServerSocket;  				// Listening server socket
packetBuffer connBuffer[SOCKETTABLESIZE];	// DosBOX
Bit8u inBuffer[IPXBUFFERSIZE];				// DosBOX
IPaddress ipconn[SOCKETTABLESIZE];  		// Active TCP/IP connection 
Uint16 port;								// UDP port to listen
char device[20];							// Interface name
bool use_llc = true; // Use Logical Link Control (IEEE 802.2)

// From DosBox
void UnpackIP(PackedIP ipPack, IPaddress * ipAddr) {
	ipAddr->host = ipPack.host;
	ipAddr->port = ipPack.port;
}

// From DosBox
void PackIP(IPaddress ipAddr, PackedIP *ipPack) {
	ipPack->host = ipAddr.host;
	ipPack->port = ipAddr.port;
}

// Convert MAC address to printable string
void mac_to_string(const u_char mac[], char *str)
{
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// From DosBox ipxserver.cpp - send packet to connected host
void sendIPXPacket(Bit8u *buffer, Bit16s bufSize) {
	Bit16u srcport, destport;
	Bit32u srchost, desthost;
	Bit16u i;
	Bits result;
	UDPpacket outPacket;
	outPacket.channel = -1;
	outPacket.data = buffer;
	outPacket.len = bufSize;
	outPacket.maxlen = bufSize;
	IPXHeader *tmpHeader;
	tmpHeader = (IPXHeader *)buffer;

	srchost = tmpHeader->src.addr.byIP.host;
	desthost = tmpHeader->dest.addr.byIP.host;

	srcport = tmpHeader->src.addr.byIP.port;
	destport = tmpHeader->dest.addr.byIP.port;
	

	if(desthost == 0xffffffff) {
		// Broadcast
		for(i=0;i<SOCKETTABLESIZE;i++) {
			if(connBuffer[i].connected && ((ipconn[i].host != srchost)||(ipconn[i].port!=srcport))) {
				outPacket.address = ipconn[i];
				result = SDLNet_UDP_Send(ipxServerSocket,-1,&outPacket);
				if(result == 0) {
					printf("IPXSERVER: %s\n", SDLNet_GetError());
					continue;
				}
			}
		}
	} else {
		// Specific address
		for(i=0;i<SOCKETTABLESIZE;i++) {
			if((connBuffer[i].connected) && (ipconn[i].host == desthost) && (ipconn[i].port == destport)) {
				outPacket.address = ipconn[i];
				result = SDLNet_UDP_Send(ipxServerSocket,-1,&outPacket);
				if(result == 0) {
					printf("IPXSERVER: %s\n", SDLNet_GetError());
					continue;
				}
			}
		}
	}
}

// From DosBox ipxserver.cpp - acknowledge a new connection
static void ackClient(IPaddress clientAddr) {
	IPXHeader regHeader;
	UDPpacket regPacket;
	Bits result;

	SDLNet_Write16(0xffff, regHeader.checkSum);
	SDLNet_Write16(sizeof(regHeader), regHeader.length);
	
	SDLNet_Write32(0, regHeader.dest.network);
	PackIP(clientAddr, &regHeader.dest.addr.byIP);
	SDLNet_Write16(0x2, regHeader.dest.socket);

	SDLNet_Write32(1, regHeader.src.network);
	PackIP(ipxServerIp, &regHeader.src.addr.byIP);
	SDLNet_Write16(0x2, regHeader.src.socket);
	regHeader.transControl = 0;

	regPacket.data = (Uint8 *)&regHeader;
	regPacket.len = sizeof(regHeader);
	regPacket.maxlen = sizeof(regHeader);
	regPacket.address = clientAddr;
	// Send registration string to client.  If client doesn't get this, client will not be registered
	result = SDLNet_UDP_Send(ipxServerSocket,-1,&regPacket);
	if(result == 0) {
		printf("IPXSERVER: %s\n", SDLNet_GetError());
	}
}

// From DosBox ipxserver.cpp - receive packet and hand over to other clients
// Modified to also send the packet to real interface using pcap
void IPX_ServerLoop() {
	UDPpacket inPacket;
	IPaddress tmpAddr;

	Bit16u i;
	Bit32u host;
	Bits result;

	inPacket.channel = -1;
	inPacket.data = &inBuffer[0];
	inPacket.maxlen = IPXBUFFERSIZE;

	result = SDLNet_UDP_Recv(ipxServerSocket, &inPacket);
	if (result != 0) {
		// Check to see if incoming packet is a registration packet
		// For this, I just spoofed the echo protocol packet designation 0x02
		IPXHeader *tmpHeader;
		tmpHeader = (IPXHeader *)&inBuffer[0];
	
		// Check to see if echo packet
		if(SDLNet_Read16(tmpHeader->dest.socket) == 0x2) {
			// Null destination node means its a server registration packet
			if(tmpHeader->dest.addr.byIP.host == 0x0) {
				UnpackIP(tmpHeader->src.addr.byIP, &tmpAddr);
				for(i=0;i<SOCKETTABLESIZE;i++) {
					if(!connBuffer[i].connected) {
						// Use prefered host IP rather than the reported source IP
						// It may be better to use the reported source
						ipconn[i] = inPacket.address;

						connBuffer[i].connected = true;
						host = ipconn[i].host;
						printf("IPXSERVER: Connect from %d.%d.%d.%d\n", CONVIP(host));
						ackClient(inPacket.address);
						return;
					} else {
						if((ipconn[i].host == tmpAddr.host) && (ipconn[i].port == tmpAddr.port)) {

							printf("IPXSERVER: Reconnect from %d.%d.%d.%d\n", CONVIP(tmpAddr.host));
							// Update anonymous port number if changed
							ipconn[i].port = inPacket.address.port;
							ackClient(inPacket.address);
							return;
						}
					}
					
				}
			}
		}

		// IPX packet is complete.  Now interpret IPX header and send to respective IP address
		sendIPXPacket((Bit8u *)inPacket.data, inPacket.len);

		// Create and send packet received from DosBox to the real network
		unsigned char ethernet[1500];

		// Ethernet source and destination MACs are replicated from IPX header
		memcpy(ethernet, tmpHeader->dest.addr.byNode.node, 6);
		memcpy(ethernet+6, tmpHeader->src.addr.byNode.node, 6);

		// Ethernet packet length
		u_short ether_packet_len = inPacket.len + (use_llc ? ENCAPSULE_LEN : 0);
		ether_packet_len = (ether_packet_len>>8) | (ether_packet_len<<8); // Swap endianess
		memcpy(&ethernet[ETHER_ADDR_LEN * 2], &ether_packet_len, sizeof(ether_packet_len));
		
		// IPX over IP
		if (use_llc) {
			ethernet[ETHER_HEADER_LEN + 0] = 0xe0;
			ethernet[ETHER_HEADER_LEN + 1] = 0xe0;
			ethernet[ETHER_HEADER_LEN + 2] = 0x03;
		}

		// IPX
		memcpy(&ethernet[ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)], inPacket.data, inPacket.len);

		// Actual send
		if (pcap_sendpacket(handle, &ethernet[0], ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0) + inPacket.len) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(handle));
		}
		else
		{
			printf("box  -> real, IPX len=%i\n", inPacket.len);
		}
	}
}

// From DosBox ipxserver.cpp, stop the ipxnet server
void IPX_StopServer() {
	SDLNet_UDP_Close(ipxServerSocket);
}

// From DosBox ipxserver.cpp, start the ipxnet server
bool IPX_StartServer(Bit16u portnum) {
	Bit16u i;

	if(!SDLNet_ResolveHost(&ipxServerIp, NULL, portnum)) {
	
		ipxServerSocket = SDLNet_UDP_Open(portnum);
		if(!ipxServerSocket) return false;

		for(i=0;i<SOCKETTABLESIZE;i++) connBuffer[i].connected = false;

		return true;
	}
	return false;
}

// Capture real packets with pcap and send them to dosbox network
void pcap_to_dosbox()
{
	struct pcap_pkthdr header;	// The header that pcap gives us
	const u_char *packet;		// The actual packet
	char smac[20], dmac[20];
	
	packet = pcap_next(handle, &header);
	if ((packet != 0) && (header.len >= (14 + 3)))
	{
		const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);
		mac_to_string(ethernet->ether_shost, &smac[0]);
		mac_to_string(ethernet->ether_dhost, &dmac[0]);
		
		#ifdef DEBUG
		printf("Captured packet, len=%d, src=%s, dest=%s, ether_type=%i\n", header.len, smac, dmac, ethernet->ether_type);
		#endif
		
		// Send to DOSBox
		IPXHeader *tmpHeader = (IPXHeader *)(packet + ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0));
		sendIPXPacket((Bit8u *)tmpHeader, header.len - (ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)));

		printf("real -> box , IPX len=%i\n", header.len - (ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)));
	}
}

// Clean shutdown, used by signal
void clean_shutdown(int signum)
{
	printf("\nClean shutdown\n");
	pcap_close(handle);
	IPX_StopServer();
	exit(signum);
}

// Main program
int main(int argc, char *argv[])
{
	int port = 213;
	bool help = false;
	int c;

	while ((c = getopt (argc, argv, "p:rh")) != -1)
		switch (c)
		{
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			use_llc = false;
			break;
		case 'h':
			help = true;
		case '?':
			exit(1);
		default:
			abort();
		}

	// Command line parameters
	if (optind+1 != argc || help)
	{
		errx(1, "Usage: %s IF [-p PORT]\n\n"
		     "Forwards IPX traffic between network interface "
		     "IF where the real\ncomputers are located and DOSBox "
		     "IPXNET.\n\nParameters:\n"
		     " -p  UDP port where DOSBox connects to, defaults to 213\n"
		     " -r  Use Novell raw IEEE 802.3 instead of LLC (IEEE 802.2)",
		     argv[0]);
	}

	strncpy(device, argv[optind], sizeof(device));

	// Open interface that has real DOS machine, in promiscuous mode
	handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);
	if (!handle)
	{
		printf("Couldn't open device %s for pcap: %s\n", device, errbuf);
		return 1;
	}
	else
	{
		printf("Opened device %s for pcap\n", device);
	}

	// Start DosBox IPX server
	if (IPX_StartServer(port))
	{
		printf("DosBox IPX server started at port %i\n", port);
	}
	else
	{
		printf("Couldn't start DosBox IPX server\n");
		return 1;
	}

 	// Craft an SDL_net pollable pcap socket
	struct Pcap_Socket sdlnet_pcap = {0, pcap_get_selectable_fd(handle)};
	if (sdlnet_pcap.channel == PCAP_ERROR) {
		errx(1, "Unable to get fd from pcap device\n");
	}
	
	// Create SDL_net socket set
	SDLNet_SocketSet socketSet = SDLNet_AllocSocketSet(2);
	if(!socketSet) {
		errx(1, "SDLNet_AllocSocketSet: %s\n", SDLNet_GetError());
	}
	if (SDLNet_UDP_AddSocket(socketSet, ipxServerSocket) == -1) {
		errx(1, "SDLNet_AddSocket: %s\n", SDLNet_GetError());
	}
	if (SDLNet_UDP_AddSocket(socketSet, &sdlnet_pcap) == -1) {
		errx(1, "SDLNet_AddSocket: %s\n", SDLNet_GetError());
	}
	
	printf("\nYou can now write somewhere, on some DOSBox(es):\nIPXNET CONNECT <this host's ip> %i\n", port);
	printf("Then, start IPX networking on real DOS computer(s) connected to %s.\n", device);
	printf("Now you can start playing IPX games between them.\n\n");

	// Use CTRL-C or SIGTERM to exit
	signal(SIGINT, clean_shutdown);
	signal(SIGTERM, clean_shutdown);

	// Main loop for exchanging packets and accepting connections
	for(;;)
	{
		SDLNet_CheckSockets(socketSet, -1);
		if (sdlnet_pcap.ready) {
			pcap_to_dosbox();
			// Setting socket status manually to non-ready
			// because read it outside SDLNet.
			sdlnet_pcap.ready = 0;
		}
		if (SDLNet_SocketReady(ipxServerSocket)) {
			IPX_ServerLoop();
		}
	}

	return 0;
}
