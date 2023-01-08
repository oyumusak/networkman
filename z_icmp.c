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

	int transmit_s, receive_s, rc;
	struct protoent *p;
	struct sockaddr_in sin;
	struct ip ip;
	struct icmp icmp;

	if (argc != 2)
		errx(EX_USAGE, "%s <dest_addr>", argv[0]);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = 0;

	/* Parse command line address. */
	if (inet_pton(PF_INET, argv[1], &sin.sin_addr) <= 0)
		err(EX_USAGE, "Parse address");

	transmit_s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (transmit_s < 0)
		err(EX_OSERR, "transmit_s raw socket");

	/* Fill in the IP header. */
	memset(&ip, 0x0, sizeof(ip));
	ip.ip_v = IPVERSION;
	ip.ip_hl = sizeof(ip) >> 2;
	ip.ip_tos = 0;
	ip.ip_len = sizeof(ip) + sizeof(icmp);
	ip.ip_id = htons(getpid());
	ip.ip_off = 0;
	ip.ip_ttl = MAXTTL;
	ip.ip_p = IPPROTO_RAW;
	ip.ip_sum = cksum((unsigned short *)&ip, sizeof(ip));
	ip.ip_src.s_addr = inet_addr("10.28.28.28");
	ip.ip_dst.s_addr = inet_addr(argv[1]);

	/* Fill in the ICMP header. */
	memset(&icmp, 0x0, sizeof(icmp));
	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_id = getpid();
	icmp.icmp_seq = 1;
	icmp.icmp_cksum = cksum((unsigned short *)&icmp, sizeof(icmp));

	/* Send it off. */
	rc = sendto(transmit_s, &icmp, sizeof(icmp), 0, (struct sockaddr *)&sin, sizeof(sin));
	if (rc < 0)
	{
		err(EX_OSERR, "sendto");
	}

sendto (sfd, buf, 28, 0, SA & addr, sizeof addr);
sendto (sfd, buf, sizeof(struct ip) + sizeof(struct icmphdr), 0, SA & addr, sizeof addr);

recvfrom (sfd, buff, 28, 0, SA & addr2, &len);
recvfrom (sfd, buff, sizeof(buff), 0, SA & addr2, &len);



	fprintf(stdout, "SENT %d BYTES\n", rc);
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

	close(transmit_s);
	fprintf(stdout, "Closed transmit_s\n\n");

	// receiver socket // PF or AF_INET doesnt matter
	// IPPROTO_RAW is 255 unknown protocol and dont get a response
	receive_s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
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

	close(receive_s);
	fprintf(stdout, "Closed receive_s\n\n");

	return 0;
}
