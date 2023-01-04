// https://www.tcpdump.org/pcap.html

// pcap_decode.c - a simple packet sniffer using libpcap
// compile: gcc pcap_decode.c -lpcap
// run: ./a.out

#include <pcap.h>        // for pcap_t, pcap_datalink(), pcap_next_ex(), pcap_open_live(), pcap_close()
#include "00_hing.h"     // for fatal ec_malloc and dump
#include "00_network.h"  // send_string receive_line and so on

// it's already defined in pcap.h and its equal to 65536
// it's already defined in stdio.h and its equal to 1024
#define BUFSIZ 4096 // best practice is to define your own buffer size

void pcap_fatal(const char *failed_in, const char *err_bff);
void decode_ethernet(const u_char *packet);
void decode_ip(const u_char *packet);
u_int decode_tcp(const u_char *packet);

void caught_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// not using args for now
int main(int argc, char **argv) // argc = number of arguments, argv = array of arguments
{
    struct pcap_pkthdr *header;     // The header that pcap gives us
    u_char *packet, *pkt_data;      // The actual packet to send -- const removed for assignable pointer
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
    char *device = NULL;            // Will be set to "eth0"
    pcap_t *pcap_handle;            // pcap_handle is a pointer to a pcap_t structure

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
        pcap_fatal("pcap_lookupdev", errbuf);

    printf("\n ! Active ethernet device: %s\n", device);
    // pcap_open_live arguments: device, snaplen, promiscuous mode, timeout, error buffer
    pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);  // pcap_open_live() returns a pointer to a pcap_t structure.
    if (pcap_handle == NULL)                  // If the pointer is NULL, an error occurred
        pcap_fatal("pcap_open_live", errbuf);   // Print the error

    // pcap_loop(pcap_handle, -1, caught_packet, NULL);
    pcap_loop(pcap_handle, 3, caught_packet, NULL);
    
    pcap_close(pcap_handle);    // close the pcap handle
}

void caught_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    u_int tcp_header_length, total_header_size, pkt_data_len;
    u_char *pkt_data;

    printf("\n");
	printf("=== got a %d bytes of packet ====\n", header->len);

    decode_ethernet(packet);         // Decode the ethernet header
    decode_ip(packet+ETHER_HDR_LEN); // Decode the IP header
    tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

    total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
    pkt_data = (u_char *)packet + total_header_size;
    pkt_data_len = header->len - total_header_size;
    if (pkt_data_len > 0) 
    {
		printf("\t\t\t%u bytes of packet data\n\n", pkt_data_len);
        dump(pkt_data, pkt_data_len); // Dump the packet data
        // printf("==== end of packet ====\n");
    } 
    else { printf("\t\t\tNo packet data\n\n"); }
}

void pcap_fatal(const char *failed_in, const char *err_bff)
{
    fprintf(stderr, "Fatal error in %s: %s\n", failed_in, err_bff);
    exit(1);    // Exit with error
}

void decode_ethernet(const u_char *header_start)
{
    int i;  // Loop counter
    struct ether_hdr *ethernet_header;  // Pointer to the ethernet header

    ethernet_header = (struct ether_hdr *)header_start;
	printf("[[  Layer 2 :: Ethernet Header  ]]\n");
    printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", ethernet_header->ether_src_addr[i]);
    // funny looking hex output, but it's the way it is
	printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
	for(i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start)
{
    struct ip_hdr *ip_header;
    // it's not a pointer, it's a structure
    ip_header = (struct ip_hdr *)header_start;
	printf("\t((  Layer 3 ::: IP Header  ))\n");
	// printf("\t( Source: %s\t", inet_ntoa(ip_header->ip_src_addr));
    // error: passing 'unsigned int' to parameter of incompatible type 'struct in_addr'
    // solution: cast to 'struct in_addr'
    printf("\t( Source: %u\t", ip_header->ip_src_addr);
    // cast to same spell:
	// printf("Dest: %s )\n", inet_ntoa(ip_header->ip_dest_addr));
    printf("Dest: %u )\n", ip_header->ip_dest_addr);
	printf("\t( Type: %u\t", (u_int) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
/*
    printf("[ Version: %u\t", ip_header->ip_version);
    printf("Header Length: %u\t", ip_header->ip_hdr_len);
    printf("TOS: %u\t", ip_header->ip_tos);
    printf("Total Length: %u\t", ip_header->ip_total_len);
    printf("Identification: %u\t", ip_header->ip_id);
    printf("Flags: %u\t", ip_header->ip_flags);
    printf("Fragment Offset: %u\t", ip_header->ip_frag_offset);
    printf("TTL: %u\t", ip_header->ip_ttl);
    printf("Protocol: %u\t", ip_header->ip_protocol);
    printf("Checksum: %u\t", ip_header->ip_checksum);
    printf("Source: %u\t", ip_header->ip_src);
    printf("Destination: %u ]\n", ip_header->ip_dest);
*/
}

u_int decode_tcp(const u_char *header_start)
{
    struct tcp_hdr *tcp_header;
    u_int tcp_header_length;
    // it's not what it looks like, it's a structure
    tcp_header = (struct tcp_hdr *)header_start;
	tcp_header_length = 4 * tcp_header->tcp_offset;

	printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
	printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
	printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
	printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
	printf("\t\t{ Header Size: %u\tFlags: ", tcp_header_length);
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	printf(" }\n");
    
    // tcp_header_length = tcp_header->tcp_hdr_len * 4;
	return tcp_header_length;
/*
    printf("\t\t( Source: %hu\t", ntohs(tcp_header->tcp_src_port));
    printf("Dest: %hu )\n", ntohs(tcp_header->tcp_dest_port));
    printf("\t\t( Sequence Number: %u\t", ntohl(tcp_header->tcp_seq_num));
    printf("Acknowledgement Number: %u\t", ntohl(tcp_header->tcp_ack_num));
    printf("Header Length: %u\t", tcp_header->tcp_hdr_len);
    printf("Flags: %u\t", tcp_header->tcp_flags);
    printf("Window Size: %u\t", ntohs(tcp_header->tcp_win_size));
    printf("Checksum: %u\t", ntohs(tcp_header->tcp_checksum));
    printf("Urgent Pointer: %u )\n", ntohs(tcp_header->tcp_urg_ptr));

    tcp_header_length = tcp_header->tcp_hdr_len * 4;
    return tcp_header_length;
*/
}
