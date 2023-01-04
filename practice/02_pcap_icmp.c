/*  A standardized programming library called libpcap can be used to
    smooth out the inconsistencies of raw sockets. The functions in
    this library still use raw sockets to do their magic, but the
    library knows how to correctly work with raw sockets on multiple
    architectures. Both tcpdump and dsniff use libpcap, which allows
    them to compile with relative ease on any platform.
    
    Raw packet sniffer program using the libpcap's functions */

// When the program is compiled, the pcap library must be linked with -l pcap.

// The pcap library is a standard library that provides a set of functions
// that can be used to read and write packets from/to a network interface.

// pcap_icmp.c - a simple packet sniffer using libpcap
// compile: gcc pcap_icmp.c -lpcap
// run: ./a.out

// ICMP REQUEST

#include <stdlib.h>      // for exit()
#include <stdio.h>       // for printf()
#include <pcap.h>        // for pcap_t, pcap_datalink(), pcap_next_ex(), pcap_open_live(), pcap_close()
#include "00_hing.h"     // for fatal ec_malloc and dump

// #define BUFSIZ 65536
#define BUFSIZ 4096

void pcap_fatal(const char *failed_in, const char *err_bff)
{
    fprintf(stderr, "Fatal error in %s: %s\n", failed_in, err_bff);
    exit(1);
}

int main (int argc, char **argv) 
{
    /* Define the device */
    struct pcap_pkthdr *header;     // The header that pcap gives us
    u_char *packet;                 // The actual packet to send -- const removed for assignable pointer
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
    char *device = NULL;            // Will be set to "eth0"
    pcap_t *pcap_handle;            // pcap_handle is a pointer to a pcap_t structure
    int i;                          // A counter

    /* Find the device with pcap_lookupdev used to capture the packets */
    /* ---------------------------------------------------------------- */

    // 'pcap_lookupdev' is deprecated: use 'pcap_findalldevs' and use the first device in the list
    // device = pcap_findalldevs(&device, errbuf);
    // I was tried to use pcap_findalldevs but it didn't work
    
    // Well at least this is the way to do it
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        pcap_fatal("pcap_lookupdev", errbuf);
    }

    /*  Print the device name */
    printf("Active ethernet device: %s\n", device);

    /* Open the device for sniffing */
    // pcap_open_live arguments: device, snaplen, promiscuous mode, timeout, error buffer
    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);  // pcap_open_live() returns a pointer to a pcap_t structure.
    if (pcap_handle == NULL) {                  // If the pointer is NULL, an error occurred
        pcap_fatal("pcap_open_live", errbuf);   // Print the error
    }

    /* Send icmp packet */
    for (i = 0; i < 1; i++) // Send 1 packet.
    {
        /* Ethernet Header */
        /* Destination MAC - 6 octets: ff:ff:ff:ff:ff:ff */
        packet[0]=0xff;
        packet[1]=0xff;
        packet[2]=0xff;
        packet[3]=0xff;
        packet[4]=0xff;
        packet[5]=0xff;
        /* Source MAC - 6 octets: 54:42:49:02:31:8c */
        packet[6]=0x54;
        packet[7]=0x42;
        packet[8]=0x49;
        packet[9]=0x02;
        packet[10]=0x31;
        packet[11]=0x8c;
        /* Protocol Type - 2 octets: 0x0800 (IP) */
        packet[12]=0x08;
        packet[13]=0x00;

        /* IP Packet */
        /* IP Version - 4 bits: 4 */
        packet[14]=0x45;
        /* IP Header Length - 4 bits: 20 bytes */
        packet[15]=0x00;
        /* IP Type of Service - 8 bits: 0 */
        packet[16]=0x00;
        /* IP Total Length - 16 bits: 20 bytes */
        packet[17]=0x00;
        packet[18]=0x14;
        /* IP Identification - 16 bits: 0 */
        packet[19]=0x00;
        packet[20]=0x00;
        /* IP Flags - 3 bits: 0 */
        packet[21]=0x00;
        /* IP Fragment Offset - 13 bits: 0 */
        packet[22]=0x00;
        packet[23]=0x00;
        /* IP Time to Live - 8 bits: 64 */
        packet[24]=0x40;
        /* IP Protocol - 8 bits: 6 (TCP) 0x06 */
        packet[25]=0x06;
        /* IP Header Checksum - 16 bits: 0 */
        packet[26]=0x00;
        packet[27]=0x00;
        /* IP Source Address - 32 bits: 10.28.28.28 */
        packet[28]=0x0a;
        packet[29]=0x1c;
        packet[30]=0x1c;
        packet[31]=0x1c;
        /* IP Destination Address - 32 bits: 10.28.28.1 */
        packet[32]=0x0a;
        packet[33]=0x1c;
        packet[34]=0x1c;
        packet[35]=0x01;

        /* ICMP Packet */
        /* ICMP Type - 8 bits: 8 (Echo Request) 0x08 */
        packet[36]=0x08;
        /* ICMP Code - 8 bits: 0 */
        packet[37]=0x00;
        /* ICMP Checksum - 16 bits: 0 */
        packet[38]=0x00;
        packet[39]=0x00;
        /* ICMP Identifier - 16 bits: 0 */
        packet[40]=0x00;
        packet[41]=0x00;
        /* ICMP Sequence Number - 16 bits: 0 */
        packet[42]=0x00;
        packet[43]=0x00;
        /* ICMP timestamp - 32 bits: 0 */
        packet[44]=0x00;
        packet[45]=0x00;
        packet[46]=0x00;
        packet[47]=0x00;
        /* ICMP data - 32 bits: test */
        packet[48]=0x74;
        packet[49]=0x65;
        packet[50]=0x73;
        packet[51]=0x74;

        /* Send the packet */
        // pcap_sendpacket arguments: pcap_t, packet, length
        if (pcap_sendpacket(pcap_handle, packet, 52) != 0) {
            pcap_fatal("pcap_sendpacket", pcap_geterr(pcap_handle));
        }

        /* Wait for the packet to be sent */
        // pcap_next_ex arguments: pcap_t, pcap_pkthdr **, u_char **
        // pcap_next_ex returns: 0 if no packet is available, 1 if a packet is available, -1 if an error occurred
        if (pcap_next_ex(pcap_handle, &header, &packet) != 1) {
            pcap_fatal("pcap_next_ex", pcap_geterr(pcap_handle));
        }

        /* Send down the packet */
        printf("Packet number %d sent\n", i);
        printf("Packet received: %d bytes\n", header->len);
        printf("Ethernet Header:\n");
        printf("\tFrom: %02x:%02x:%02x:%02x:%02x:%02x\n",
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
        printf("\tTo: %02x:%02x:%02x:%02x:%02x:%02x\n",
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
        printf("\tType: 0x%04x\n",
            (packet[12] << 8) + packet[13]);
        printf("IP Header:\n");
        printf("\tVersion: %d\n", (packet[14] & 0xf0) >> 4);
        printf("\tHeader Length: %d\n", (packet[14] & 0x0f) * 4);
        printf("\tType of Service: %d\n", packet[16]);
        printf("\tTotal Length: %d\n", (packet[17] << 8) + packet[18]);
        printf("\tIdentification: %d\n", (packet[19] << 8) + packet[20]);
        printf("\tFlags: 0x%02x\n", packet[21] >> 5);
        printf("\tFragment Offset: %d\n", ((packet[22] & 0x1f) << 8) + packet[23]);
        printf("\tTime to Live: %d\n", packet[24]);
        printf("\tProtocol: %d\n", packet[25]);
        printf("\tHeader Checksum: 0x%04x\n", (packet[26] << 8) + packet[27]);
        printf("\tSource IP: %d.%d.%d.%d\n",
            packet[28], packet[29], packet[30], packet[31]);
        printf("\tDestination IP: %d.%d.%d.%d\n",
            packet[32], packet[33], packet[34], packet[35]);
        printf("ICMP Header:\n");
        printf("\tType: %d\n", packet[36]);
        printf("\tCode: %d\n", packet[37]);
        printf("\tChecksum: 0x%04x\n", (packet[38] << 8) + packet[39]);
        printf("\tIdentifier: %d\n", (packet[40] << 8) + packet[41]);
        printf("\tSequence Number: %d\n", (packet[42] << 8) + packet[43]);
        printf("\tTimestamp: %d\n", (packet[44] << 24) + (packet[45] << 16) + (packet[46] << 8) + packet[47]);
        printf("\tData: %s\n", packet + 48);

        printf("Packet data : \n");         // Print the packet data
        dump(packet, header->len);          // dump() is defined in pcap_util.c
    }
}

/*  Notice that there are many bytes preceding the sample text in the packet and
    many of these bytes are similar. Since these are raw packet captures, most of 
    these bytes are not important. The important bytes are the Ethernet header,
    IP header, and ICMP header.

    The Ethernet header is 14 bytes long. 
    The IP header is 20 bytes long. 
    The ICMP header is 8 bytes long.
*/
