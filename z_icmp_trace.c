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

int main(int argc, char *argv[])
{
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

	fprintf(stdout, "traceroute to %s, %d hops max, %d byte packets \n", argv[2], MAXTTL, 28);

	for (int i = 0; i < packet_count; i++)
	{
		clock_t start_time = clock();
		transmit_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (transmit_s < 0)
			err(EX_OSERR, "error open transmit_s raw socket on %s to %s", argv[0], argv[2]);

		int one = 1;
		const int *val = &one;
		if (setsockopt(transmit_s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{ perror("setsockopt() IP_HDRINCL error"); exit(-1); }

		/* set deadline */
		struct timeval tv;
		tv.tv_sec = 1;  /* 1 Sec Timeout */
		tv.tv_usec = 0;  // Not init'ing this can cause strange errors
		if (setsockopt(transmit_s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)))
		{ perror("setsockopt() SO_RCVTIMEO error"); exit(-1); }


		/* ICMP header. */
		memset(&icmp, 0x0, sizeof(icmp));
		icmp.icmp_type = ICMP_ECHO;
		icmp.icmp_code = 0;
		icmp.icmp_cksum = 0;
		icmp.icmp_id = htons(getpid());
		icmp.icmp_seq = htons(0);    // sequence number for traceroute packet is 0
		icmp.icmp_cksum = cksum((unsigned short *)&icmp, sizeof(icmp));

		/* IP header */
		ip.ip_hl = 5;
		ip.ip_v = 4;
		ip.ip_tos = IPTOS_MINCOST;
		ip.ip_len = sizeof(struct ip) + sizeof(struct icmp);
		ip.ip_id = htons(getpid());
		ip.ip_off = 0;
		ip.ip_ttl = i + 1;
		ip.ip_p = IPPROTO_ICMP;
		ip.ip_sum = 0;
		ip.ip_src.s_addr = inet_addr(argv[1]);
		ip.ip_dst.s_addr = inet_addr(argv[2]);
		ip.ip_sum = cksum((unsigned short *)&ip, sizeof(ip));

		/* packet */
		char packet[4096];
		memcpy(packet, &ip, sizeof(ip));
		memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));

		/* send the request. */
		rc = sendto(transmit_s, packet, ip.ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) { err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", rc, errno); }
		close(transmit_s);

		/* receive the response. */
		receive_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (receive_s < 0)
			err(EX_OSERR, "error open receive_s raw socket on %s to %s", argv[0], argv[2]);

		u_char buffer[4096];
		struct ip *ip_recv = (struct ip *)buffer;
		struct icmp *icmp_recv = (struct icmp *)(buffer + (ip_recv->ip_hl << 2));

		/* set deadline */
		struct timeval tv_recv;
		tv_recv.tv_sec = 1;  /* 1 Sec Timeout */
		tv_recv.tv_usec = 0;  // Not init'ing this can cause strange errors
		if (setsockopt(receive_s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_recv, sizeof(struct timeval)))
		{ printf("setsockopt() SO_RCVTIMEO error"); }

		socklen_t sinlen = sizeof(sin);
		ret = recvfrom(receive_s, &buffer, sizeof(buffer), 0, (struct sockaddr *)&sin, &sinlen);
		if (ret != -1) 
		{ 
			clock_t end_time = clock();
			float time_taken = (float)(end_time - start_time);
			time_taken = (float)(time_taken * 10) / 1000;

			// if packet_count is 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 then print the packet count
			if (i < 9) { fprintf(stdout, " %d %s      \t%f ms\n", i + 1, inet_ntoa(ip_recv->ip_src), time_taken); }
			else { fprintf(stdout, "%d %s      \t%f ms\n", i + 1, inet_ntoa(ip_recv->ip_src), time_taken); }
			close(receive_s);
		}
		else 
		{ 
			// if packet_count is 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 then print the packet count
			if (i < 9) { fprintf(stdout, " %d * * *\n", i + 1); }
			else { fprintf(stdout, "%d * * *\n", i + 1); }
			close(receive_s); 
		}

		if (ip_recv->ip_src.s_addr == ip.ip_dst.s_addr) { break; }
	}
	return 0;
}