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
unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
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

	for (int i = 1; i < 31; i++)
	{
		// int x = i + 1;
		// delay((x * 2) + 1); // wait for (i*2)+1 hops, then send out next packet
			
		int transmit_s, receive_s, rc;
		struct protoent *p;
		struct sockaddr_in sin;

		if (argc != 2)
			errx(EX_USAGE, "Usage: %s <IP address>", argv[0]);

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		
		/* Parse command line address. */
		if (inet_pton(AF_INET, argv[1], &sin.sin_addr) <= 0)
			err(EX_USAGE, "Parse address");

		/* open raw socket */
		transmit_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (transmit_s < 0)
			err(EX_OSERR, "error open transmit_s raw socket on %s to %s", argv[0], argv[1]);
		
		// IP PROTO RAW or IP PROTO ICMP ?
		int one = 1;
		const int *val = &one;
		if (setsockopt(transmit_s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
			printf("Warning: Cannot set HDRINCL!\n");


		/* Fill in the IP & ICMP header. */
		u_char buf[4096] = { 0 };
		struct ip *ip = (struct ip *) (buf);
		struct icmp *icmp = (struct icmp *) (buf + sizeof(struct ip));

		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		ip->ip_tos = 0;
		ip->ip_len = sizeof(struct ip) + sizeof(struct icmp);
		ip->ip_id = getpid();
		ip->ip_off = 0;
		ip->ip_ttl = htons(i);
		ip->ip_p = IPPROTO_ICMP;
		// ip->ip_src.s_addr = inet_addr("192.168.1.117");
		// ip->ip_dst.s_addr = inet_addr(argv[1]);
        inet_pton(AF_INET, "172.20.10.4", &(ip->ip_src.s_addr));
		inet_pton (AF_INET, argv[1], &(ip->ip_dst.s_addr));
		ip->ip_sum = csum((unsigned short *)buf, 9);

		icmp->icmp_type = ICMP_ECHO;
		icmp->icmp_code = 0;
		icmp->icmp_cksum = 0;
		icmp->icmp_id = htons(getpid());
		icmp->icmp_seq = 0;
		icmp->icmp_cksum = csum((unsigned short *)(buf + 20), 4);
	
		/* Send it off. */
		rc = sendto(transmit_s, buf, sizeof(struct ip) + sizeof(struct icmp), 0, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) { err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", rc, errno); }
		else 
		{
			fprintf(stdout, "\n\nSENT %d BYTES\n", rc);
			fprintf(stdout, "-------------\n");
			/*
			fprintf(stdout, "src  IP\t\t: %s\n", inet_ntoa(ip->ip_src));
			fprintf(stdout, "dst  IP\t\t: %s\n", inet_ntoa(ip->ip_dst));
			fprintf(stdout, "IP ID\t\t: %d\n", ip->ip_id);
			fprintf(stdout, "ICMP ID\t\t: %d\n", icmp->icmp_id);
			fprintf(stdout, "ICMP Type\t: %d\n", icmp->icmp_type);
			fprintf(stdout, "ICMP Code\t: %d\n", icmp->icmp_code);
			fprintf(stdout, "Seq Number\t: %d\n", htons(icmp->icmp_seq));
			fprintf(stdout, "ICMP Checksum\t: %d\n", icmp->icmp_cksum);
			fprintf(stdout, "TTL\t\t: %d\n", ip->ip_ttl);
			dump((unsigned char *)&icmp, rc);
			*/
		} 

		/* Receive it back. */
		u_char buffer[4096] = {0};
		struct sockaddr_in sin2;
		socklen_t sin2len = sizeof(sin2);

		int ret = recvfrom(transmit_s, buffer, sizeof(buffer), 0, (struct sockaddr *)&sin2, &sin2len);
		if (ret < 0) { err(EX_OSERR, "error recvfrom recvlen=%d error no = %d\n", ret, errno); }

		fprintf(stdout, "RECV %d BYTES\n", ret);
		fprintf(stdout, "-------------\n");

		// received packet
		struct ip *ip_recv = (struct ip *)buffer;
		struct icmp *icmp_recv = (struct icmp *) (buffer + sizeof(struct ip));
		/*
		fprintf(stdout, "src  IP\t\t: %s\n", inet_ntoa(ip_recv->ip_src));
		fprintf(stdout, "dst  IP\t\t: %s\n", inet_ntoa(ip_recv->ip_dst));
		fprintf(stdout, "ICMP ID\t\t: %d\n", ntohs(icmp_recv->icmp_id));
		fprintf(stdout, "ICMP Type\t: %d\n", icmp_recv->icmp_type);
		fprintf(stdout, "ICMP Code\t: %d\n", icmp_recv->icmp_code);
		fprintf(stdout, "Seq Number\t: %d\n", ntohl(icmp_recv->icmp_seq));
		fprintf(stdout, "ICMP Checksum\t: %d\n", icmp_recv->icmp_cksum);
		dump((unsigned char *)&icmp_recv, ret);
		*/
		fprintf(stdout, "\nhop limit:%d Address:%s\n", i, inet_ntoa(sin2.sin_addr));
		fprintf(stdout, "\nhop limit:%d Address:%s\n", i, inet_ntoa(ip->ip_src));
		fprintf(stdout, "\nhop limit:%d Address:%s\n", i, inet_ntoa(ip->ip_dst));
		fprintf(stdout, "\nhop limit:%d Address:%s\n", i, inet_ntoa(ip_recv->ip_src));
		fprintf(stdout, "\nhop limit:%d Address:%s\n", i, inet_ntoa(ip_recv->ip_dst));

		
	}
	return 0;
}