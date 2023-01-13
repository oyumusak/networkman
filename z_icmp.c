#include <stdio.h>					// printf() and fprintf() 
#include <stdlib.h>					// atoi() and exit() 
#include <unistd.h> 				// close(), read(), write() and getopt() 
#include <string.h>					// memset(), bzero(), and bcopy() 
#include <fcntl.h>					// fcntl(), F_GETFL, and F_SETFL 
#include <pthread.h>				// pthread_create(), pthread_join(), pthread_mutex_lock(), pthread_mutex_unlock(), pthread_cond_wait(), pthread_cond_signal(), and pthread_cond_broadcast()
#include <arpa/inet.h>			// inet_ntoa()
#include <sys/types.h>			// struct sockaddr
#include <sys/socket.h>			// socket(), connect(), sendto(), and recvfrom()
#include <sys/time.h>				// struct timeval and gettimeofday()
#include <netdb.h>					// struct hostent and gethostbyname() 
#include <netinet/in.h>			// struct sockaddr_in and htons()
#include <netinet/ip.h> 		// struct iphdr and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>// struct icmphdr and ICMP_ECHO
#include <err.h>						// err() and errx() 
#include <sysexits.h>				// EX_USAGE and EX_OSERR
#include <errno.h>					// errno, perror(), and strerror() 

/* this is a simple ICMP ping program */
// sudo tcpdump -i any host 10.100.4.1 and 10.100.4.147
// sudo tcpdump -i any host 192.168.1.117 and host 8.8.8.8
// 178.244.204.193

// dumps raw memory in hex byte and printable split format
void dump(const unsigned char *data_buffer, const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i < length; i++) {
		byte = data_buffer[i];
		fprintf(stdout, "%02x ", data_buffer[i]);  // display byte in hex
		if(((i%16)==15) || (i==length-1)) {
			for(j=0; j < 15-(i%16); j++)
				fprintf(stdout, "   ");
			fprintf(stdout, "| ");
			for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)) // outside printable char range
					fprintf(stdout, "%c", byte);
				else
					fprintf(stdout, ".");
			}
			fprintf(stdout, "\n"); // end of the dump line (each line 16 bytes)
		} // end if
	} // end for
}


// generic checksum calculation algorithm
unsigned short cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}


void delay(int number_of_seconds)
{
	// Approximating to meet enough delay, so that my icmp listener has enough time to go to I/O burst and get back to listening
	int approx_time = 10000 * number_of_seconds;
	// Stroing start time
	clock_t start_time = clock();
	// looping till required time is not acheived
	while (clock() < start_time + approx_time)
		printf(""); //"%d\n",clock());
	;
}


int main(int argc, char *argv[])
{
	/* this buffer will contain ip header, tcp header,
		 and payload. we'll point an ip header structure
		 at its beginning, and a tcp header structure after
		 that to write the header values into it */
	int packet_count = atoi(argv[3]);
	int transmit_s, receive_s, rc, ret;
	struct protoent *p;
	struct sockaddr_in sin;
	struct ip ip;
	struct icmp icmp;

	if (argc != 4)
		errx(EX_USAGE, "Usage: %s <source_addr> <dest_addr> <packet_count>", argv[0]);
	else if (argv[1] == NULL)
		errx(EX_USAGE, "Usage: %s <source_addr> <dest_addr> <packet_count>", argv[0]);
	else if (argv[2] == NULL)
		errx(EX_USAGE, "Usage: %s <source_addr> <dest_addr> <packet_count>", argv[0]);
	else if (argv[3] == NULL)
		errx(EX_USAGE, "Usage: %s <source_addr> <dest_addr> <packet_count>", argv[0]);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	/* Parse source address. */
	if (inet_pton(AF_INET, argv[1], &sin.sin_addr) <= 0)
		err(EX_USAGE, "Parse address");

	/* Parse destination address. */
	if (inet_pton(AF_INET, argv[2], &sin.sin_addr) <= 0)
		err(EX_USAGE, "Parse address");


	for (int i = 0; i < packet_count; i++)
	{

		/* open raw socket */
		transmit_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (transmit_s < 0)
			err(EX_OSERR, "error open transmit_s raw socket on %s to %s", argv[0], argv[2]);

		/* set socket option to tell the kernel that
			we provide the IP structure */
		int one = 1;
		const int *val = &one;
		if (setsockopt(transmit_s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{ perror("setsockopt() error"); exit(-1); }


		/* Fill in the ICMP header. */
		memset(&icmp, 0x0, sizeof(icmp));
		icmp.icmp_type = ICMP_ECHO;
		icmp.icmp_code = 0;
		icmp.icmp_cksum = 0;
		icmp.icmp_id = htons(getpid());

		// TODO: -T flag for traceroute mode (set sequence number 0)
		icmp.icmp_seq = htons(0);    // sequence number for traceroute packet is 0
		// icmp.icmp_seq = htons(i); // sequence number for dummy ping packet is i
		icmp.icmp_cksum = cksum((unsigned short *)&icmp, sizeof(icmp));

		/* IP header */
		ip.ip_hl = 5;
		ip.ip_v = 4;
		ip.ip_tos = 0;
		ip.ip_len = sizeof(struct ip) + sizeof(struct icmp);
		ip.ip_id = htons(getpid());
		ip.ip_off = 0;

		// TODO: -T flag for traceroute mode (set ttl to i+1)
		ip.ip_ttl = i + 1; // ttl for traceroute packet
		// ip.ip_ttl = MAXTTL; // max ttl 255 for dummy ping packet
		ip.ip_p = IPPROTO_ICMP;
		ip.ip_sum = 0;
		ip.ip_src.s_addr = inet_addr(argv[1]);
		ip.ip_dst.s_addr = inet_addr(argv[2]);
		ip.ip_sum = cksum((unsigned short *)&ip, sizeof(ip));

		/* packet */
		char packet[4096];
		memcpy(packet, &ip, sizeof(ip));
		memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));

		/* Send the request. */
		rc = sendto(transmit_s, packet, ip.ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) { err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", rc, errno); }

		fprintf(stdout, "\n  SENT %d BYTES\n", rc);
		fprintf(stdout, "-----------------\n");
		fprintf(stdout, "ID\t: %d\n", ntohs(icmp.icmp_id));
		fprintf(stdout, "Src\t: %s\n", inet_ntoa(ip.ip_src));
		fprintf(stdout, "Dest\t: %s\n", inet_ntoa(ip.ip_dst));
		fprintf(stdout, "Type\t: %d\n", icmp.icmp_type);
		fprintf(stdout, "Code\t: %d\n", icmp.icmp_code);
		fprintf(stdout, "Seq\t: %d\n", htons(icmp.icmp_seq));
		fprintf(stdout, "TTL\t: %d\n", ip.ip_ttl);
		dump((unsigned char *)&icmp, rc);
		close(transmit_s);
		

		

		/* Receive the response. */
		receive_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		u_char buffer[1500];
		socklen_t sinlen = sizeof(sin);
		ret = recvfrom(receive_s, &buffer, sizeof(buffer), 0, (struct sockaddr *)&sin, &sinlen);

		fprintf(stdout, "\n  RECV %d BYTES\n", rc);
		fprintf(stdout, "-----------------\n");

		// received packet
		struct ip *ip_recv = (struct ip *)buffer;
		struct icmp *icmp_recv = (struct icmp *)(buffer + (ip_recv->ip_hl << 2));
		fprintf(stdout, "ID\t: %d\n", ntohs(icmp_recv->icmp_id));
		fprintf(stdout, "Src\t: %s\n", inet_ntoa(ip_recv->ip_src));
		fprintf(stdout, "Dst\t: %s\n", inet_ntoa(ip_recv->ip_dst));
		fprintf(stdout, "Type\t: %d\n", icmp_recv->icmp_type);
		fprintf(stdout, "Code\t: %d\n", icmp_recv->icmp_code);
		fprintf(stdout, "Seq\t: %d\n", htons(icmp_recv->icmp_seq));
		fprintf(stdout, "TTL\t: %d\n", ip_recv->ip_ttl);
		dump((unsigned char *)&icmp_recv, ret);
		
		close(receive_s);
		
	}

	return 0;
}