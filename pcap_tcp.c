/*
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Usage: cap_packet [packet_count]
 * Example: ./cap_packet 8
 *
 ****************************************************************************
 *
 * Example compiler command-line for GCC:
 *  gcc -Wall -pedantic -Wextra -Wunreachable-code -g cap_packet.c -lpcap
 *  
 ****************************************************************************
 *
 */

#include <pcap.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <ctype.h> 
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
// #include <netinet/ether.h>  // for linux/ubuntu ethernet header
// #include <time.h>  // for linux/ubuntu time
#include <net/ethernet.h>
#include <netinet/ip.h> 

/* Structure for Ethernet headers */
#ifndef ETHER_ADDR_LEN 
#define ETHER_ADDR_LEN      0x6
#endif

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN       0x14
#endif

/*  802.3 header - IEEE Ethernet - Static header size: 14 bytes */
/*  Ethernet II header is the same as IEEE 802.3 header, but the type field is replaced by the length field. */
struct _802_3_hdr
{
    uint8_t  _802_3_dhost[ETHER_ADDR_LEN];  /* destination ethernet address */
    uint8_t  _802_3_shost[ETHER_ADDR_LEN];  /* source ethernet address */
    uint16_t _802_3_len;                    /* packet type ID */
};

/* Structure for Internet Protocol (IP) headers */
/* IPv4 header - Static header size: 20 bytes */
struct ipv4_hdr
{
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* Structure for Transmission Control Protocol (TCP) headers */
/* TCP header - Transmission Control Protocol - Static header size: 20 bytes */
struct tcp_hdr {
   unsigned short tcp_src_port;   // source TCP port
   unsigned short tcp_dest_port;  // destination TCP port
   unsigned int tcp_seq;          // TCP sequence number
   unsigned int tcp_ack;          // TCP acknowledgement number
   unsigned char reserved:4;      // 4-bits from the 6-bits of reserved space
   unsigned char tcp_offset:4;    // TCP data offset for little endian host
   unsigned char tcp_flags;       // TCP flags (and 2-bits from reserved space)
#define TCP_FIN   0x01
#define TCP_SYN   0x02
#define TCP_RST   0x04
#define TCP_PUSH  0x08
#define TCP_ACK   0x10
#define TCP_URG   0x20
   unsigned short tcp_window;     // TCP window size
   unsigned short tcp_checksum;   // TCP checksum
   unsigned short tcp_urgent;     // TCP urgent pointer
};

struct in_addr addr;            // Used for both ip & subnet
struct pcap_pkthdr cap_header;
u_char packet[99];           	// packet that pcap gives us
const u_char *pkt_data;         // packet data
char errbuf[PCAP_ERRBUF_SIZE];  // buffer to hold error string

pcap_t *pcap_handle;            // Handle of the device that shall be sniffed
pcap_if_t *device;    		    // List of all devices

char *network_address;          // IP address of the network
char *network_mask;             // IP mask of the network

char *device_name;              // name of the device to sniff on
char *device_description;       // description of the device to sniff on

bpf_u_int32 maskp;          	// subnet mask
bpf_u_int32 netp;           	// ip address

struct bpf_program fp;          // holds compiled program

u_int packet_count = 0;
u_char *args = NULL;

void my_callback(u_char *, const struct pcap_pkthdr *, const u_char *);

u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* cap_header,const u_char*packet);
u_char* handle_IP(u_char *args,const struct pcap_pkthdr* cap_header,const u_char*packet);
u_int handle_tcp(const u_char *packet);
void dump(const unsigned char *data_buffer, const unsigned int length);

int main(int argc,char **argv)
{
    // Options must be passed in as a string because I am lazy
    if(argc < 2){ 
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }

    // "use 'pcap_findalldevs' and use the first device"
    if(pcap_findalldevs(&device, errbuf) == -1)
    {
        fprintf(stderr, "Error pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    if(pcap_lookupnet(device->name, &netp, &maskp, errbuf) == -1)
    {
        fprintf(stderr, "Error pcap_lookupnet: %s\n", errbuf);
        exit(1);
    }

    // "open the device"
    if((pcap_handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf)) == NULL)
    { fprintf(stderr, "Error pcap_open_live: %s\n", errbuf); exit(1); }

    // "compile the filter"
    if(pcap_compile(pcap_handle, &fp, "ip", 0, netp) == -1)
    { fprintf(stderr, "Error p_compile: %s\n", pcap_geterr(pcap_handle)); exit(1); }

    // "set the filter"
    if(pcap_setfilter(pcap_handle, &fp) == -1)
    { fprintf(stderr, "Error setfilter: %s\n", pcap_geterr(pcap_handle)); exit(1); }

    // summary of the sniffer
    fprintf(stdout,"+-----------------------------------------+\n");
    fprintf(stdout,"| Device  : %-20s          |\n",device->name);
    fprintf(stdout,"| Descrip : %-20s          |\n",device->description);

    addr.s_addr = netp;
    network_address = inet_ntoa(addr);
    if(network_address == NULL)
    {
        fprintf(stderr, "Error in inet_ntoa:network_address\n");
        exit(1);
    }
    fprintf(stdout,"| Network : %-20s          |\n",network_address);
    
    addr.s_addr = maskp;
    network_mask = inet_ntoa(addr);

    if(network_mask == NULL)
    {
        perror("inet_ntoa:network_mask");
        exit(1);
    }
    fprintf(stdout,"| Netmask : %-20s          |\n",network_mask);
    fprintf(stdout,"+-----------------------------------------+\n");

    // "start sniffing"
    if(pcap_loop(pcap_handle, -1, my_callback, NULL) == -1)
    {
        fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(pcap_handle));
        exit(1);
    }

    // "close the device"
    pcap_close(pcap_handle);

    // "free the list of devices"
    pcap_freealldevs(device);
}

void my_callback(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
	int tcp_header_length, total_header_size, pkt_data_len;
	u_char *pkt_data;

    fprintf(stdout,"\n");
    fprintf(stdout,"#%d", ++packet_count);
    fprintf(stdout,"  Data: %d", cap_header->len);
    fprintf(stdout,"  Captured: %d", cap_header->caplen);
    fprintf(stdout,"  Seconds: %d", cap_header->ts.tv_usec);
    fprintf(stdout,"  Time: %s", ctime((const time_t *)&cap_header->ts.tv_sec));

    u_int16_t type = handle_ethernet(args,cap_header,packet);

    if(type == ETHERTYPE_IP)
    { 
        handle_IP(args,cap_header,packet); 
        tcp_header_length = handle_tcp(packet+ETHER_HDR_LEN+sizeof(struct ipv4_hdr));

        total_header_size = ETHER_HDR_LEN + sizeof(struct ipv4_hdr) + tcp_header_length;
        pkt_data = (u_char *)packet + total_header_size;
        pkt_data_len = cap_header->len - total_header_size;
        if (pkt_data_len > 0) 
        {
            fprintf(stdout,"\t\t\t%u bytes of packet data\n\n", pkt_data_len);
            dump(pkt_data, pkt_data_len); // Dump the packet data
            fprintf(stdout,"==== end of packet ====\n");
        } 
        else { fprintf(stdout,"\t\t\tNo packet data\n\n"); }
    }
    else if(type == ETHERTYPE_ARP)
    {/* handle arp packet */}
    else if(type == ETHERTYPE_REVARP)
    {/* handle reverse arp packet */}
}

/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* cap_header,const u_char*packet)
{
    u_int caplen = cap_header->caplen;
    u_int length = cap_header->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDR_LEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    fprintf(stdout,"    [ Layer 2 :: 802.3 Ethernet Header ] [ packet_length: %d ]\n",length);
    fprintf(stdout,"    [ Source: %s",ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"  Dest: %s",ether_ntoa((struct ether_addr*)eptr->ether_dhost));
    fprintf(stdout," Type: 0x%.4x ", ntohs(eptr->ether_type));

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    { fprintf(stdout,"(IP) ]\n"); }
    else  if (ether_type == ETHERTYPE_ARP)
    { fprintf(stdout,"(ARP) ]\n"); }
    else  if (eptr->ether_type == ETHERTYPE_REVARP)
    { fprintf(stdout,"(RARP) ]\n"); }
    else { fprintf(stdout,"(?) ]\n"); }

    return ether_type;
}

u_char* handle_IP(u_char *args,const struct pcap_pkthdr* cap_header,const u_char *packet)
{
    const struct ipv4_hdr *ip_header;
    u_int length = cap_header->len;
    u_int hlen,off,version;
    u_int len;

    /* jump pass the ethernet header */
    ip_header = (struct ipv4_hdr*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct ipv4_hdr))
    { fprintf(stdout,"truncated ip %d",length); return NULL; }

    len     = ntohs(ip_header->ip_len);
    hlen    = IP_HL(ip_header); /* header length */
    version = IP_V(ip_header);/* ip version */

    /* check version */
    if(version != 4) { fprintf(stdout,"Unknown version %d\n",version); return NULL; }

    /* check header length */
    if(hlen < 5 ) { fprintf(stdout,"bad-hlen %d \n",hlen); }

    /* see if we have as much packet as we should */
    if(length < len) { fprintf(stdout,"\ntruncated IP - %d bytes missing\n",len - length); }

    /* Check to see if we have the first fragment */
    off = ntohs(ip_header->ip_off);

    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"\t[ Layer 3 :: IP Header ] [ packet_length: %d ] [ header_length: %d ]\n",len,hlen);
        fprintf(stdout,"\t[ Source: %s ",inet_ntoa(ip_header->ip_src));
        fprintf(stdout," Dest: %s (IPv%d) Offmask: %d ]\n",inet_ntoa(ip_header->ip_dst),version,off);
    }

    return NULL;
}

u_int handle_tcp(const u_char *header_start)
{
    struct tcp_hdr *tcp_header;
    u_int tcp_header_length;
    // it's not what it looks like, it's a structure
    tcp_header = (struct tcp_hdr *)header_start;
	tcp_header_length = 4 * tcp_header->tcp_offset;

	fprintf(stdout,"\t\t{{  Layer 4 :::: TCP Header  }}\n");
	fprintf(stdout,"\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
	fprintf(stdout,"Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
	fprintf(stdout,"\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	fprintf(stdout,"Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
	fprintf(stdout,"\t\t{ Header Size: %u\tFlags: ", tcp_header_length);
	if(tcp_header->tcp_flags & TCP_FIN)
		fprintf(stdout,"FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		fprintf(stdout,"SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		fprintf(stdout,"RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		fprintf(stdout,"PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		fprintf(stdout,"ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		fprintf(stdout,"URG ");
	fprintf(stdout," }\n");
    
    // tcp_header_length = tcp_header->tcp_hdr_len * 4;
	return tcp_header_length;
}

// dumps raw memory in hex byte and printable split format
void dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i < length; i++) {
		byte = data_buffer[i];
		fprintf(stdout,"%02x ", data_buffer[i]);  // display byte in hex
		if(((i%16)==15) || (i==length-1)) {
			for(j=0; j < 15-(i%16); j++)
				fprintf(stdout,"   ");
			fprintf(stdout,"| ");
			for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)) // outside printable char range
					fprintf(stdout,"%c", byte);
				else
					fprintf(stdout,".");
			}
			fprintf(stdout,"\n"); // end of the dump line (each line 16 bytes)
		} // end if
	} // end for
}
