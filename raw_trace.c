#include <stdio.h>		 // lib for printf()  and fprintf()
#include <stdlib.h>		 // lib for rand()  and exit()
#include <unistd.h>		 // lib for getpid()  and close()
#include <string.h>		 // lib for memset() and memcpy()
#include <arpa/inet.h> // lib for inet_addr() and inet_ntoa()
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <time.h>

#include <sysexits.h> // lib for EX_USAGE and EX_OSERR
#include <err.h>			// lib for err() and errx()

#define P 34555


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

	int transmit_s, receive_s, rc;
	struct protoent *p;
	struct sockaddr_in sin;
	struct ip ip;
	struct icmp icmp;

	if (argc != 2)
		errx(EX_USAGE, "Usage: %s <IP address>", argv[0]);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons (7);

	// 192.168.1.117
	
	/* Parse command line address. */
	if (inet_pton(AF_INET, argv[1], &sin.sin_addr) <= 0)
		err(EX_USAGE, "Parse address");

	/* open raw socket */
	transmit_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (transmit_s < 0)
		err(EX_OSERR, "transmit_s raw socket");

	for (int i = 1; i < 20; i++)
	{
		delay((i * 2) + 1); // wait for (i*2)+1 hops, then send out next packet
		
		/* Fill in the IP header. */
		memset(&ip, 0x0, sizeof(ip));
		ip.ip_v = IPVERSION;
		ip.ip_hl = sizeof(ip) >> 2;
		ip.ip_tos = 0;
		ip.ip_len = sizeof(ip) + sizeof(icmp);
		ip.ip_id = htons(getpid());
		ip.ip_off = 0;
		ip.ip_ttl = i;
		ip.ip_p = IPPROTO_RAW;
		ip.ip_sum = cksum((unsigned short *)&ip, sizeof(ip));
		// ip.ip_src.s_addr = inet_addr("10.28.28.28");
		// ip.ip_dst.s_addr = inet_addr(argv[1]);
		inet_pton(AF_INET, "192.168.1.117", &(ip.ip_src.s_addr));
		inet_pton (AF_INET, argv[1], &(ip.ip_dst.s_addr));
		

		/* Fill in the ICMP header. */
		memset(&icmp, 0x0, sizeof(icmp));
		icmp.icmp_type = ICMP_ECHO;
		icmp.icmp_code = 0;
		icmp.icmp_id = getpid();
		icmp.icmp_seq = 1;
		icmp.icmp_cksum = cksum((unsigned short *)&icmp, sizeof(icmp));

		/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
			 that the kernel knows the header is included in the data, and doesn't
			 insert its own header into the packet before our data;
			 got this off the internet */

		
		int one = 1;
		const int *val = &one;
		if (setsockopt(transmit_s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
			printf("Warning: Cannot set HDRINCL!\n");

		/* Send it off. */
		rc = sendto(transmit_s, &icmp, sizeof(icmp), 0, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) { err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", rc, errno); }
		else 
		{
			fprintf(stdout, "\n\nSENT %d BYTES\n", rc);
			/*
			fprintf(stdout, "-------------\n");
			fprintf(stdout, "src  IP\t\t: %s\n", inet_ntoa(ip.ip_src));
			fprintf(stdout, "dst  IP\t\t: %s\n", inet_ntoa(ip.ip_dst));
			fprintf(stdout, "IP ID\t\t: %d\n", ntohs(ip.ip_id));
			fprintf(stdout, "ICMP ID\t\t: %d\n", ntohs(icmp.icmp_id));
			fprintf(stdout, "ICMP Type\t: %d\n", icmp.icmp_type);
			fprintf(stdout, "ICMP Code\t: %d\n", icmp.icmp_code);
			fprintf(stdout, "Seq Number\t: %d\n", ntohl(icmp.icmp_seq));
			fprintf(stdout, "ICMP Checksum\t: %d\n", ntohs(icmp.icmp_cksum));
			dump((unsigned char *)&icmp, sizeof(icmp));	
			*/
		} 


		/* Receive it back. */
		receive_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		u_char buffer[1500];
		socklen_t sinlen = sizeof(sin);
		// memset(&buffer, 0x0, sizeof(buffer));
		// int ret = recv(receive_s, &buffer, sizeof(buffer), 0);
		int ret = recvfrom(receive_s, &buffer, sizeof(buffer), 0, (struct sockaddr *)&sin, &sinlen);

		fprintf(stdout, "RECV %d BYTES\n", ret);
		fprintf(stdout, "-------------\n");

		// received packet
		struct ip *ip_recv = (struct ip *)buffer;
		struct icmp *icmp_recv = (struct icmp *)(buffer + (ip_recv->ip_hl << 2));
		fprintf(stdout, "src  IP\t\t: %s\n", inet_ntoa(ip_recv->ip_src));
		fprintf(stdout, "dst  IP\t\t: %s\n", inet_ntoa(ip_recv->ip_dst));
		fprintf(stdout, "ICMP ID\t\t: %d\n", ntohs(icmp_recv->icmp_id));
		fprintf(stdout, "ICMP Type\t: %d\n", icmp_recv->icmp_type);
		fprintf(stdout, "ICMP Code\t: %d\n", icmp_recv->icmp_code);
		fprintf(stdout, "Seq Number\t: %d\n", ntohl(icmp_recv->icmp_seq));
		fprintf(stdout, "ICMP Checksum\t: %d\n", ntohs(icmp_recv->icmp_cksum));
		dump((unsigned char *)&icmp_recv, ret);
		
	}
	return 0;
}