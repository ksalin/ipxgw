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

//Adjustments for Ethernet and UniPCemu-compatible allocation by Superfury

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "config.h"
#include <unistd.h>
#include <pcap.h>
#include "SDL_net.h"
#include <signal.h>
#include <err.h>
#include <sys/time.h> //Timekeeping!

#define ETHER_ADDR_LEN 6				// Ethernet addresses are 6 bytes, for use with pcap
#define ETHER_HEADER_LEN 14				// Ethernet header is two addresses and two bytes size, for use with pcap
#define ENCAPSULE_LEN 3					// Header for encapsulating IPX to Ethernet, for use with pcap
#define SOCKETTABLESIZE 16				// From DosBox
#define CONVIP(hostvar) hostvar & 0xff, (hostvar >> 8) & 0xff, (hostvar >> 16) & 0xff, (hostvar >> 24) & 0xff 	// From DosBox
#define CONVIPX(hostvar) hostvar[0], hostvar[1], hostvar[2], hostvar[3], hostvar[4], hostvar[5]					// From DosBox
#define IPXBUFFERSIZE 1424				// From DosBox
#undef DEBUG							// More output if defined
//Define below if you want to debug the network number functionality.
//#define DEBUGNW

//Timeout until a IPX node number is decided to be usable. Replies to the echo reset the timer until none reply within the timeout after the request.
#define ALLOCATE_IPXNODE_ECHO_TIMEOUT 500000

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
	Bit8u connected;		// Connected flag. 0=Not connected, 1=Connected, 2=Requesting address by trying a echo with timeout.
	bool waitsize;
	//Timer for checking if a client exists.
	Bit64u timer;
	struct timeval timerlast;
	struct timeval timernow;
	//End of timer variables.
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
IPaddress ipconnAssigned[SOCKETTABLESIZE];  		// Active TCP/IP connection's assigned IPX address!
Uint32 ipconnNetwork[SOCKETTABLESIZE]; //The network number of the client!
Uint16 port;								// UDP port to listen
char device[20];							// Interface name
bool use_llc = true; // Use Logical Link Control (IEEE 802.2)
bool use_ethernetii = false; // Use Logical Link Control (IEEE 802.2)
Uint32 use_IPXnetworknumber = 0; // Used network number for all clients!

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

//Below IPX address functions and some reserved addresses copied from UniPCemu.
//result: 1 for OK address. 0 for overflow! NULL and Broadcast and special addresses are skipped automatically. addrsizeleft should be 6 (the size of an IPX address)
//Some reserved IPX addresses for special use (taken from UniPCemu)!
uint8_t ipxbroadcastaddr[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF }; //IPX Broadcast address
uint8_t ipxnulladdr[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 }; //IPX Forbidden NULL address
uint8_t ipx_servernodeaddr[6] = { 0x00,0x00,0x00,0x00,0x00,0x01 }; //IPX server node address!
uint8_t ipx_servernetworknumber[4] = { 0x00,0x00,0x00,0x01 }; //Server network number!
uint8_t incIPXaddr2(uint8_t* ipxaddr, uint8_t addrsizeleft) //addrsizeleft=6 for the address specified
{
	uint8_t result;
	uint8_t originaladdrsize;
	originaladdrsize = addrsizeleft; //How much is left?
	if (!addrsizeleft) return 0; //Nothing to allocate anymore?
	++*ipxaddr; //Increase the address!
	result = 1; //Default: OK!
	if (*ipxaddr == 0) //Overflow?
	{
		result = incIPXaddr2(--ipxaddr, --addrsizeleft); //Try the next upper byte!
	}
	addrsizeleft = originaladdrsize; //What were we processing?
	if (addrsizeleft == 6) //No overflow for full address?
	{
		if (memcmp(ipxaddr - 5, &ipxbroadcastaddr, sizeof(ipxbroadcastaddr)) == 0) //Broadcast address? all ones.
		{
			return incIPXaddr2(ipxaddr, 6); //Increase to the first address, which we'll use!
		}
		if (memcmp(ipxaddr - 5, &ipxnulladdr, sizeof(ipxnulladdr)) == 0) //Null address? all zeroes.
		{
			return incIPXaddr2(ipxaddr, addrsizeleft); //Increase to the first address, which we'll use!
		}
		if (memcmp(ipxaddr - 5, &ipx_servernodeaddr, sizeof(ipx_servernodeaddr)) == 0) //Server address? ~01
		{
			return incIPXaddr2(ipxaddr, 6); //Increase to the next possible address, which we'll use!
		}
	}
	return result; //Address is OK, if we've not overflown!
}

//ipxaddr must point to the first byte of the address (it's in big endian format)
uint8_t incIPXaddr(uint8_t* ipxaddr)
{
	return incIPXaddr2(&ipxaddr[5], 6); //Increment the IPX address to a valid address from the LSB!
}

uint8_t IPXaddrused(uint8_t* ipxaddr, Bit16u *ignoreentry)
{
	uint8_t rawipxaddr[6];
	Bit16u i;
	for (i=0;i<SOCKETTABLESIZE;++i)
	{
		if (ignoreentry)
		{
			if (i==*ignoreentry)
			{
				continue;
			}
		}
		if (!connBuffer[i].connected)
		{
			continue;
		}
		memcpy(&rawipxaddr[0], &ipconnAssigned[i].host, 4); //Host!
		memcpy(&rawipxaddr[4], &ipconnAssigned[i].port, 2); //Port!
		if (memcmp(ipxaddr,&rawipxaddr,6)==0) //Found?
		{
			return connBuffer[i].connected; //Give the status!
		}
	}
	return 0; //Not connected or pending allocation!
}

//DESTNETWORKFILTER
//And met any condition for the destination network (destination network 'current network' (zero) is only when source network is detected ours)?
#define DESTNETWORKFILTER (dstnetworkcur & ((srcnetworkcur >> 1) | (srcnetworkcur >> 2) | srcnetworkcur | 6))
//COMMONNETFILTER 
//Source network current or broadcast?
//Destination network current or broadcast?
#define COMMONNETFILTER srcnetworkcur = (((!srcnetwork) ? 1 : 0) | ((srcnetwork == ipconnNetwork[i]) ? 2 : 0) | ((srcnetwork == 0xFFFFFFFF) ? 4 : 0)); \
	dstnetworkcur = (((!dstnetwork) ? 1 : 0) | ((dstnetwork == ipconnNetwork[i]) ? 2 : 0) | ((dstnetwork == 0xFFFFFFFF) ? 4 : 0));


// From DosBox ipxserver.cpp - send packet to connected host
void sendIPXPacket(Bit8u *buffer, Bit16s bufSize) {
	Bit16u srcport, destport;
	Bit32u srchost, desthost;
	Bit16u i;
	Bits result;
	Bit32u srcnetwork, dstnetwork;
	Bit8u srcnetworkcur, dstnetworkcur; //Flags reflecting different network conditions
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
	
	srcnetwork = SDLNet_Read32(tmpHeader->src.network); //Source network!
	dstnetwork = SDLNet_Read32(tmpHeader->dest.network); //Destination network!

	srcnetworkcur = dstnetworkcur = 0; //Init!

	if((desthost == 0xffffffff) /* && (destport == 0xFFFF)*/) { //IPX node broadcast (this is officially both the host and port part having all bits set)?
		// Broadcast
		for(i=0;i<SOCKETTABLESIZE;i++) {
			if(connBuffer[i].connected==1) { //Ready for use?
				COMMONNETFILTER
				#ifdef DEBUGNW
				printf("Test BC network %08x: src=%08x dst=%08x ours=%08x srcflags=%01x, dstflags=%01x\n", i, srcnetwork, dstnetwork, ipconnNetwork[i],srcnetworkcur,dstnetworkcur); //Log it for testing!
				#endif
				if (
					(!((ipconnAssigned[i].host == srchost)&&(ipconnAssigned[i].port==srcport)&&(srcnetworkcur&1))) && //Not from ourselves on our own network?
					DESTNETWORKFILTER //And met any condition for the destination network (destination network 'current network' (zero) is only when source network is detected ours)?
					) { //Valid to receive on this client?
					#ifdef DEBUGNW
					printf("Accepted condition!\n");
					#endif
					outPacket.address = ipconn[i];
					result = SDLNet_UDP_Send(ipxServerSocket,-1,&outPacket);
					if(result == 0) {
						printf("IPXSERVER: %s\n", SDLNet_GetError());
						continue;
					}
				}
			}
		}
	} else {
		// Specific address
		for(i=0;i<SOCKETTABLESIZE;i++) {
			if(connBuffer[i].connected==1) { //Ready for use?
				COMMONNETFILTER
				#ifdef DEBUGNW
				printf("Test UC network %08x: src=%08x dst=%08x ours=%08x srcflags=%01x, dstflags=%01x\n", i, srcnetwork, dstnetwork, ipconnNetwork[i], srcnetworkcur, dstnetworkcur); //Log it for testing!
				#endif
				if ((ipconnAssigned[i].host == desthost) && (ipconnAssigned[i].port == destport) &&
					DESTNETWORKFILTER) { //Conditions match the client (on current or specified network)?
					#ifdef DEBUGNW
					printf("Accepted condition!\n");
					#endif
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
}

// From DosBox ipxserver.cpp - acknowledge a new connection
static void ackClient(int client) {
	Bit32u sendlen;
	IPaddress clientAddr;
	IPaddress assignedAddr;
	IPXHeader regHeader;
	UDPpacket regPacket;
	memcpy(&clientAddr, &ipconn[client], sizeof(clientAddr)); //The clients host address and port!
	memcpy(&assignedAddr, &ipconnAssigned[client], sizeof(assignedAddr)); //The clients assigned address and port!
	Bits result;
	unsigned char ethernet[1500];

	SDLNet_Write16(0xffff, regHeader.checkSum);
	SDLNet_Write16(sizeof(regHeader), regHeader.length);
	
	//Dosbox-compatible values here:
	SDLNet_Write32(ipconnNetwork[client], regHeader.dest.network); //Assigned network number!
	PackIP(assignedAddr, &regHeader.dest.addr.byIP);
	SDLNet_Write16(0x2, regHeader.dest.socket);

	SDLNet_Write32(ipconnNetwork[client], regHeader.src.network);
	PackIP(ipxServerIp, &regHeader.src.addr.byIP);
	SDLNet_Write16(0x2, regHeader.src.socket);
	regHeader.transControl = 1; //Prevent deadlock by checking this field (identify this as a reply)!

	regPacket.data = (Uint8 *)&regHeader;
	regPacket.len = sizeof(regHeader);
	regPacket.maxlen = sizeof(regHeader);
	regPacket.address = clientAddr; //Client's real address and port it's listening on!
	// Send registration string to client.  If client doesn't get this, client will not be registered
	result = SDLNet_UDP_Send(ipxServerSocket,-1,&regPacket);
	if(result == 0) {
		printf("IPXSERVER: %s\n", SDLNet_GetError());
		return; //Abort and don't perform the Ethernet ACK as well!
	}
	printf("ACK           -> box, IPX len=%i\n", regPacket.len);

	//Also let the host network know that we allocated if on a Ethernet II network!
	if (use_ethernetii) //Ethernet II used?
	{
		// Create and send packet received from DosBox to the real network
		memset(&ethernet, 0, sizeof(ethernet)); //Clear!

		ethernet[0] = ethernet[1] = ethernet[2] = ethernet[3] = ethernet[4] = ethernet[5] = 0xFF; //Destination: broadcast!
		memcpy(ethernet + 6, regHeader.src.addr.byNode.node, 6); //Source: node!
		ethernet[12] = 0x81;
		ethernet[13] = 0x37; //IPX over ethernet!

		//Slight modification in the packet for the ACK on the host network! From assigned address to server node address to register (if any is listening)!
		SDLNet_Write32(ipconnNetwork[client], regHeader.src.network);
		PackIP(assignedAddr, &regHeader.src.addr.byIP);
		SDLNet_Write16(0x2, regHeader.src.socket);

		memcpy(&regHeader.dest.network,&ipx_servernetworknumber,4);
		memcpy(&regHeader.dest.addr.byNode.node,&ipx_servernodeaddr,6); //Send to the a packet server registration, if any is listening and/or allocating!
		SDLNet_Write16(0x2, regHeader.dest.socket);

		// IPX
		memcpy(&ethernet[ETHER_HEADER_LEN], regPacket.data, regPacket.len);
		sendlen = ETHER_HEADER_LEN + regPacket.len; //Length to send!

		// Actual send
		if (pcap_sendpacket(handle, &ethernet[0], sendlen) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(handle));
		}
		else
		{
			printf("ACK           -> real, IPX len=%i\n", regPacket.len);
		}
	}
}

// Adjusted from DosBox ipxserver.cpp - check a new connection for availability by echo.
static void requestClientEcho(int client) {
	Bit32u sendlen;
	IPaddress clientAddr;
	IPaddress assignedAddr;
	IPXHeader regHeader;
	UDPpacket regPacket;
	unsigned char ethernet[1500];
	memcpy(&clientAddr, &ipconn[client], sizeof(clientAddr)); //The clients host address and port!
	memcpy(&assignedAddr, &ipconnAssigned[client], sizeof(assignedAddr)); //The clients assigned address and port!

	SDLNet_Write16(0xffff, regHeader.checkSum);
	SDLNet_Write16(sizeof(regHeader), regHeader.length);

	//Send it back to the client's requested address! This will also where it's returned to!
	SDLNet_Write32(ipconnNetwork[client], regHeader.src.network);
	PackIP(assignedAddr, &regHeader.src.addr.byIP);
	SDLNet_Write16(0x2, regHeader.src.socket);

	//And send from us (and received from them) as a broadcast!
	SDLNet_Write32(ipconnNetwork[client], regHeader.dest.network);
	memset(&regHeader.dest.addr.byNode.node, 0xFF, 6); //Broadcast it!
	SDLNet_Write16(0x2, regHeader.dest.socket);
	regHeader.transControl = 0;

	regPacket.data = (Uint8*)&regHeader;
	regPacket.len = sizeof(regHeader);
	regPacket.maxlen = sizeof(regHeader);
	regPacket.address = clientAddr; //Client's real address and port it's listening on!

	printf("alloc request -> box, IPX len=%i\n", regPacket.len);

	//Send to all Dosbox-clients to detect if they're used!
	sendIPXPacket(regPacket.data, regPacket.len); //Send to all Dosbox clients!

	//Also let the host network know that we are trying to allocate if on a Ethernet II network!
	if (use_ethernetii) //Ethernet II used?
	{
		// Create and send packet received from DosBox to the real network
		memset(&ethernet, 0, sizeof(ethernet)); //Clear!

		ethernet[0] = ethernet[1] = ethernet[2] = ethernet[3] = ethernet[4] = ethernet[5] = 0xFF; //Destination: broadcast!
		ethernet[6] = ethernet[7] = ethernet[8] = ethernet[9] = ethernet[10] = ethernet[11] = 0xFF; //Source: broadcast!
		ethernet[12] = 0x81;
		ethernet[13] = 0x37; //IPX over ethernet!

		// IPX
		memcpy(&ethernet[ETHER_HEADER_LEN], regPacket.data, regPacket.len);
		sendlen = ETHER_HEADER_LEN + regPacket.len; //Length to send!

		// Actual send
		if (pcap_sendpacket(handle, &ethernet[0], sendlen) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(handle));
		}
		else
		{
			printf("alloc request -> real, IPX len=%i\n", regPacket.len);
		}
	}

	//Initialize timers to setup a timeout!
	gettimeofday(&connBuffer[client].timernow, NULL); //Init current time for timekeeping!
	memcpy(&connBuffer[client].timerlast, &connBuffer[client].timernow, sizeof(connBuffer[client].timerlast)); //Copy to make them equal!
	connBuffer[client].timer = 0; //Initialize to nothing ticked yet!
}

// From DosBox ipxserver.cpp - receive packet and hand over to other clients
// Modified to also send the packet to real interface using pcap
void IPX_ServerLoop() {
	UDPpacket inPacket;
	IPaddress tmpAddr;
	uint8_t ipxaddr[6];

	Bit16u i;
	Bit32u host;
	Bits result;
	Bit32u sendlen;

	inPacket.channel = -1;
	inPacket.data = &inBuffer[0];
	inPacket.maxlen = IPXBUFFERSIZE;

	result = SDLNet_UDP_Recv(ipxServerSocket, &inPacket);
	if (result != 0) {
		// Check to see if incoming packet is a registration packet
		// For this, I just spoofed the echo protocol packet designation 0x02
		IPXHeader *tmpHeader;
		tmpHeader = (IPXHeader *)&inBuffer[0];
		++tmpHeader->transControl; //Received, so increase the transport control field!

		if (SDLNet_Read32(tmpHeader->src.network)==0) { //Own network needs patching?
			for(i=0;i<SOCKETTABLESIZE;i++) {
				if(connBuffer[i].connected==1) {
					if (memcmp(&inPacket.address,&ipconn[i],4)==0) { //Found client?
						SDLNet_Write32(ipconnNetwork[i], tmpHeader->dest.network); //Fixup source network to client network!
					}
				}
			}		
		}
		
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
						ipconnAssigned[i] = inPacket.address;
						if (use_ethernetii) //Request the connection IPX node number first?
						{
							connBuffer[i].connected = 2; //Requesting IPX address from the host!
							//Send a echo request packet on the host network to detect for collisions on used addresses!

							//Setup the client's network number now!
							ipconnNetwork[i] = use_IPXnetworknumber; //The network number for this client!

							//Check for the first ipx node address to try assigning!
							memcpy(&ipxaddr[0], &ipconnAssigned[i].host, 4); //Host!
							memcpy(&ipxaddr[4], &ipconnAssigned[i].port, 2); //Port!
							for (;IPXaddrused(&ipxaddr[0],&i);) //Skip addresses that are already being requested or used!
							{
								incIPXaddr(&ipxaddr[0]); //Next available address!
								memcpy(&ipconnAssigned[i].host, &ipxaddr[0], 4); //Host!
								memcpy(&ipconnAssigned[i].port, &ipxaddr[4], 2); //Port!
							}

							requestClientEcho(i); //Request a client echo packet!
						}
						else //Just assume connected with available IPX node number!
						{
							connBuffer[i].connected = 1;
							//Setup the client's network number now!
							ipconnNetwork[i] = use_IPXnetworknumber; //The network number for this client!

							host = ipconn[i].host;
							printf("IPXSERVER: Connect from %d.%d.%d.%d\n", CONVIP(host));

							ackClient(i);
						}
						return;
					} else if (connBuffer[i].connected==1) { //Connected client might be reconnecting?
						if((ipconn[i].host == tmpAddr.host) && (ipconn[i].port == tmpAddr.port)) {

							printf("IPXSERVER: Reconnect from %d.%d.%d.%d\n", CONVIP(tmpAddr.host));
							// Update anonymous port number if changed
							ipconn[i].port = inPacket.address.port;
							ackClient(i);
							return;
						}
					}
					
				}
			}
		}

		// IPX packet is complete.  Now interpret IPX header and send to respective IP address
		sendIPXPacket((Bit8u *)inPacket.data, inPacket.len);
		printf("box           -> box, IPX len=%i\n", inPacket.len);


		// Create and send packet received from DosBox to the real network
		unsigned char ethernet[1500];
		memset(&ethernet, 0, sizeof(ethernet)); //Clear!
		--tmpHeader->transControl; //Received, don't increase the transport control field to count as a passthrough and let the receiving end apply this instead!

		if (!use_ethernetii) //Not ethernet II?
		{
			// Ethernet source and destination MACs are replicated from IPX header
			memcpy(ethernet, tmpHeader->dest.addr.byNode.node, 6);
			memcpy(ethernet + 6, tmpHeader->src.addr.byNode.node, 6);

			// Ethernet packet length
			u_short ether_packet_len = inPacket.len + (use_llc ? ENCAPSULE_LEN : 0);
			ether_packet_len = (ether_packet_len >> 8) | (ether_packet_len << 8); // Swap endianess
			memcpy(&ethernet[ETHER_ADDR_LEN * 2], &ether_packet_len, sizeof(ether_packet_len));

			// IPX over IP
			if (use_llc) {
				ethernet[ETHER_HEADER_LEN + 0] = 0xe0;
				ethernet[ETHER_HEADER_LEN + 1] = 0xe0;
				ethernet[ETHER_HEADER_LEN + 2] = 0x03;
			}

			// IPX
			memcpy(&ethernet[ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)], inPacket.data, inPacket.len);
			sendlen = ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0) + inPacket.len; //Length to send!
		}
		else //Ethernet II?
		{
			ethernet[0] = ethernet[1] = ethernet[2] = ethernet[3] = ethernet[4] = ethernet[5] = 0xFF; //Destination: broadcast!
			memcpy(ethernet + 6, tmpHeader->src.addr.byNode.node, 6); //Source: node!
			ethernet[12] = 0x81;
			ethernet[13] = 0x37; //IPX over ethernet!

			// IPX
			memcpy(&ethernet[ETHER_HEADER_LEN], inPacket.data, inPacket.len);
			sendlen = ETHER_HEADER_LEN + inPacket.len; //Length to send!
		}

		// Actual send
		if (pcap_sendpacket(handle, &ethernet[0], sendlen) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(handle));
		}
		else
		{
			printf("box           -> real, IPX len=%i\n", inPacket.len);
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
	Bit16u i;
	uint8_t ipxaddr[6];
	struct pcap_pkthdr *header;	// The header that pcap gives us
	struct pcap_pkthdr realheader;	// The header that pcap gives us
	const u_char *packet;		// The actual packet
	char smac[20], dmac[20];
	
	if (!use_ethernetii)
	{
		packet = pcap_next(handle, &realheader);
		header = &realheader;
		if ((packet != 0) && (header->len >= (14 + 3)))
		{
			const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);
			mac_to_string(ethernet->ether_shost, &smac[0]);
			mac_to_string(ethernet->ether_dhost, &dmac[0]);

#ifdef DEBUG
			printf("Captured packet, len=%d, src=%s, dest=%s, ether_type=%i\n", header.len, smac, dmac, ethernet->ether_type);
#endif

			// Send to DOSBox
			IPXHeader* tmpHeader = (IPXHeader*)(packet + ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0));
			++tmpHeader->transControl; //Received, so increase the transport control field!
			sendIPXPacket((Bit8u*)tmpHeader, header->len - (ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)));

			printf("real          -> box , IPX len=%i\n", header->len - (ETHER_HEADER_LEN + (use_llc ? ENCAPSULE_LEN : 0)));
		}
	}
	else //Ethernet II?
	{
		if (pcap_next_ex(handle,&header,&packet)<=0) return; //Poll manually!
		if ((packet != 0) && (header->len >= (14 + 30))) //Ethernet Header and IPX header minimum length?
		{
			if ((packet[12] == 0x81) && (packet[13] == 0x37)) //IPX?
			{
				// Create and send packet received from DosBox to the real network
				IPaddress tmpAddr;

				//Check for a registration packet.
				// For this, I just spoofed the echo protocol packet designation 0x02
				IPXHeader* tmpHeader;
				tmpHeader = (IPXHeader*)&packet[0x14]; //The IPX packet!
				++tmpHeader->transControl; //Received, so increase the transport control field!

				// Check to see if echo packet
				if (SDLNet_Read16(tmpHeader->dest.socket) == 0x2) {
					// Our destination node means its a server registration already used packet if allocating.
					for (i = 0; i < SOCKETTABLESIZE; i++) {
						if (connBuffer[i].connected) { //Connected or requesting?
							UnpackIP(tmpHeader->src.addr.byIP, &tmpAddr); //The requested address!
							if ((ipconnAssigned[i].host == tmpAddr.host) && (ipconnAssigned[i].port == tmpAddr.port) && (connBuffer[i].connected == 2)) { //Requesting an answer to detect in-use?
								//Convert IPX node number to a byte array, increment and try the next in range!
								memcpy(&ipxaddr[0], &ipconnAssigned[i].host, 4); //Host!
								memcpy(&ipxaddr[4], &ipconnAssigned[i].port, 2); //Port!
								incIPXaddr(&ipxaddr[0]); //Next available address!
								for (;IPXaddrused(&ipxaddr[0],&i);) //Skip addresses that are being requested or used!
								{
									incIPXaddr(&ipxaddr[0]); //Next available address!
								}
								memcpy(&ipconnAssigned[i].host, &ipxaddr[0], 4); //Host!
								memcpy(&ipconnAssigned[i].port, &ipxaddr[4], 2); //Port!
								PackIP(ipconnAssigned[i], &tmpHeader->src.addr.byIP);
								requestClientEcho(i); //Send a new client echo packet on the hosts to try the next IPX node number!
							}
						}
					}
				}

				//Normal packet!
				const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);
				mac_to_string(ethernet->ether_shost, &smac[0]);
				mac_to_string(ethernet->ether_dhost, &dmac[0]);

#ifdef DEBUG
				printf("Captured packet, len=%d, src=%s, dest=%s, ether_type=%i\n", header.len, smac, dmac, ethernet->ether_type);
#endif
				// Send to DOSBox
				tmpHeader = (IPXHeader*)(packet + ETHER_HEADER_LEN);
				sendIPXPacket((Bit8u*)tmpHeader, header->len - (ETHER_HEADER_LEN));
				printf("real          -> box , IPX len=%i\n", header->len - (ETHER_HEADER_LEN));
			}

			//Check for timers!
			for (i = 0; i < SOCKETTABLESIZE; i++) {
				if (connBuffer[i].connected == 2) { //Connected and waiting?
					memcpy(&connBuffer[i].timerlast, &connBuffer[i].timernow, sizeof(connBuffer[i].timerlast)); //Copy for checking difference!
					gettimeofday(&connBuffer[i].timernow, NULL); //Get time of day!
					connBuffer[i].timer += ((connBuffer[i].timernow.tv_sec * 1000000) + connBuffer[i].timernow.tv_usec) - ((connBuffer[i].timerlast.tv_sec * 1000000) + connBuffer[i].timerlast.tv_usec); //Time what's elapsed!
					if (connBuffer[i].timer >= ALLOCATE_IPXNODE_ECHO_TIMEOUT) //Timer elapsed without reply? The IPX node number isn't deemed to be used!
					{
						connBuffer[i].connected = 1; //Connected using the allocated address!
						ackClient(i); //Acknowledge the client!
					}
				}
			}
		}
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
	bool networkspecified = false;

	while ((c = getopt (argc, argv, "p:n:rhe")) != -1)
		switch (c)
		{
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			use_IPXnetworknumber = atoi(optarg);
			networkspecified = true; //Specified!
			break;
		case 'r':
			use_llc = false;
			break;
		case 'e':
			use_ethernetii = true; //Use Ethernet II encapsulation and server!
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
		     " -n  IPX network number to use, defaults to 0\n"
		     " -r  Use Novell raw IEEE 802.3 instead of LLC (IEEE 802.2)\n"
		     " -e  Use Ethernet II instead of 802.3/802.2",
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

	if (networkspecified) //Network number specified by the user?
	{
		printf("Using network number %i\n", use_IPXnetworknumber); //Display the network number used!
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
		else if (use_ethernetii)
		{
			pcap_to_dosbox(); //Manual update!			
		}
		if (SDLNet_SocketReady(ipxServerSocket)) {
			IPX_ServerLoop();
		}
	}

	return 0;
}
