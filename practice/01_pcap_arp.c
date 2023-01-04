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

// pcap_sniff.c - a simple packet sniffer using libpcap
// compile: gcc pcap_arp.c -lpcap
// run: ./a.out

// ARP

#include <stdlib.h>     // for exit()
#include <stdio.h>      // for printf()
#include <pcap.h>       // for pcap_t, pcap_datalink(), pcap_next_ex(), pcap_open_live(), pcap_close()
#include "00_hing.h"    // for fatal ec_malloc and dump

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

    /* Send down the packet */
    for (i = 0; i < 1; i++) // Send 3 packets.
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
        /* Ethernet Type - 2 octets: 0x0806 (ARP) */
        packet[12]=0x08;
        packet[13]=0x06;

        /* ARP Packet */
        /* Hardware type - 2 octets: Ethernet : 0x0001=Request */
        packet[14]=0x00;
        packet[15]=0x01;
        /* Protocol type - 2 octets: IP: 0x0800 */
        packet[16]=0x08;
        packet[17]=0x00;
        /* Hardware size - 1 octet: 6 */
        packet[18]=0x06;
        /* Protocol size - 1 octet: 4 */
        packet[19]=0x04;
        /* (Opcode) Operation - 2 octets: 0x0001=Request */
        packet[20]=0x00;
        packet[21]=0x01;
        /* (Sender) Source MAC - 6 octets: 54:42:49:02:31:8c */
        packet[22]=0x54;
        packet[23]=0x42;
        packet[24]=0x49;
        packet[25]=0x02;
        packet[26]=0x31;
        packet[27]=0x8c;
        /* Source IP - 4 octets: 10.28.28.28 */
        packet[28]=0x0a;
        packet[29]=0x28;
        packet[30]=0x28;
        packet[31]=0x28;
        /* (Target) Destination MAC - 6 octets: ff:ff:ff:ff:ff:ff */
        packet[32]=0xff;
        packet[33]=0xff;
        packet[34]=0xff;
        packet[35]=0xff;
        packet[36]=0xff;
        packet[37]=0xff;
        /* Destination IP - 4 octets: 10.28.28.1 */
        packet[38]=0x0a;
        packet[39]=0x28;
        packet[40]=0x28;
        packet[41]=0x01;
        
        /* Data - 28 octets: 'test packet' */
        packet[42]=0x74;
        packet[43]=0x65;
        packet[44]=0x73;
        packet[45]=0x74;
        packet[46]=0x20;
        packet[47]=0x70;
        packet[48]=0x61;
        packet[49]=0x63;
        packet[50]=0x6b;
        packet[51]=0x65;
        packet[52]=0x74;

        /* Send down the packet */
        // if (pcap_sendpacket(pcap_handle, packet, 42) != 0) {
        if (pcap_sendpacket(pcap_handle, packet, 53 /* size */) != 0 /* success */) {
            pcap_fatal("pcap_sendpacket", pcap_geterr(pcap_handle));
        }

        /* Wait for the next packet */
        if (pcap_next_ex(pcap_handle, &header, &packet) < 0) {
            pcap_fatal("pcap_next_ex", pcap_geterr(pcap_handle));
        }

        /* Print the packet */
        printf("Packet no   : %d\n", i);
        printf("Packet size : %d bytes\n", header->len);
        printf("Packet data : %s\n", packet);
        printf("Packet t1   : %s", ctime((const time_t *)&header->ts.tv_sec));
        printf("Packet t2   : %d\n", header->ts.tv_sec);
        printf("Packet t3   : %d\n", header->ts.tv_usec);
        printf("Packet data : \n");         // Print the packet data
        dump(packet, header->len);          // dump() is defined in pcap_util.c

/*
        printf("\n");
        printf("Packet data (dflt): \n");           // Print the packet data
        for (i = 0; i < header->len; i++) {         // Loop through the packet data
            printf("%02x ", packet[i]);             // Print the hex value of the byte
            if ((i + 1) % 16 == 0) {                // If we've printed 16 bytes
                printf("\n");                       // Then print a newline
            }
        }
*/

/*
        printf("\n\n");
        printf("Packet data (hing): \n");             // Print the packet data
        for (i = 0; i < header->len; i++) {           // For each octet in the packet
            packet = pcap_next(pcap_handle, &header); // pcap_next() returns a pointer to the next packet in the capture buffer.
            dump(packet, header->len);                // dump() prints the packet data
        }
        pcap_close(pcap_handle);                      // pcap_close() closes the capture handle

*/

    }
}

/*  Notice that there are many bytes preceding the sample text in the packet and
    many of these bytes are similar. Since these are raw packet captures, most of 
    these bytes are layers of header information. The first byte is the Ethernet,
    second is the IP, third is the TCP, fourth is the payload, and fifth is the
    sample text. The sample text is the text that we want to send down the wire.

    The Ethernet header is 14 bytes long.
    The IP header is 20 bytes long.
    The TCP header is 20 bytes long.
    The payload is 28 bytes long.
    The sample text is the text that we want to send down the wire.
*/
