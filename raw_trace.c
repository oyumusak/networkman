#include <stdio.h>				// lib for printf()  and fprintf()
#include <stdlib.h> 			// lib for rand()  and exit()
#include <unistd.h> 			// lib for getpid()  and close()
#include <string.h>				// lib for memset() and memcpy() 
#include <arpa/inet.h>		// lib for inet_addr() and inet_ntoa() 

#define __USE_BSD					/* use bsd'ish ip header */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#define __FAVOR_BSD				/* use bsd'ish tcp header */
#include <netinet/tcp.h>
#include <errno.h>
#include <time.h>

#include <sysexits.h> 		// lib for EX_USAGE and EX_OSERR	
#include <err.h>					// lib for err() and errx()

#define P 34555

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
    	printf("");//"%d\n",clock());
        ; 
}


int main(int argc, char *argv[])
{
		char IPADDRESS[13];
		char datagram[4096];

			/* this buffer will contain ip header, tcp header,
			   and payload. we'll point an ip header structure
			   at its beginning, and a tcp header structure after
			   that to write the header values into it */

    if (argc != 2)
        errx(EX_USAGE, "Usage: %s <IP address>", argv[0]);

    /* open raw socket */
		int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);		

    if (s < 0)
        err(EX_OSERR, "s raw socket");


		struct ip *iph = (struct ip *) datagram;
		struct tcphdr *tcph = (struct tcphdr *) datagram + sizeof (struct ip);
		struct sockaddr_in sin;

		sin.sin_family = AF_INET;
		sin.sin_port = htons(P);

				/* you byte-order >1byte header values to network
			     byte order (not needed on big endian machines) */

		/* Parse command line address. */
    if (inet_pton(AF_INET, argv[1], &sin.sin_addr) <= 0)
        err(EX_USAGE, "Parse address");

		// printf("Enter host address\n");
  	// scanf("%s", IPADDRESS);
	  // sin.sin_addr.s_addr = inet_addr (IPADDRESS);

		for (int i = 1; i < 30; i++)
		{
				delay((i * 2) + 1); // wait for (i*2)+1 hops, then send out next packet
				/* we'll now fill in the ip/tcp header values, see above for explanations */
				iph->ip_hl = 5;
				iph->ip_v = 4;
				iph->ip_tos = 0;
				iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); /* no payload */
				iph->ip_id = htonl(54321);															 /* the value doesn't matter here */
				iph->ip_off = 0;
				iph->ip_ttl = i;
				iph->ip_p = 6;
				iph->ip_sum = 0;																 /* set it to 0 before computing the actual checksum later */
				iph->ip_src.s_addr = inet_addr("192.168.1.109"); /* SYN's can be blindly spoofed */
				iph->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcph->th_sport = htons(1234); /* arbitrary port */
				tcph->th_dport = htons(P);
				tcph->th_seq = random(); 			/* in a SYN packet, the sequence is a random */
				tcph->th_ack = 0;				 			/* number, and the ack sequence is 0 in the 1st packet */
				tcph->th_x2 = 0;
				tcph->th_off = 0;						 /* first and only tcp segment */
				tcph->th_flags = TH_SYN;		 /* initial connection request */
				tcph->th_win = htonl(65535); /* maximum allowed window size */
				tcph->th_sum = 0;						 /* if you set a checksum to zero, your kernel's IP stack
														should fill in the correct checksum during transmission */
				tcph->th_urp = 0;

				iph->ip_sum = csum((unsigned short *)datagram, iph->ip_len >> 1);

				/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
					 that the kernel knows the header is included in the data, and doesn't
					 insert its own header into the packet before our data;
					 got this off the internet */

				{ /* lets do it the ugly way.. */
					int one = 1;
					const int *val = &one;
					/* IPPROTO_RAW is 255 unknown protocol and dont get a response */
					if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
						printf("Warning: Cannot set HDRINCL!\n");
				}
				int tmp = 0;
				/* send it off. */
				{
					if (tmp = sendto(s,												/* our socket */
													 datagram,								/* the buffer containing headers and data */
													 iph->ip_len,							/* total length of our datagram */
													 0,												/* routing flags, normally always 0 */
													 (struct sockaddr *)&sin, /* socket addr, just like in */
													 sizeof(sin)) == -1)
						// sizeof (sin)) < 0)		/* a normal send() */
						err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", tmp, errno);
					else
						printf(".\n");
				}
				// close(s);
				// fprintf(stdout, "Closed transmit_s\n\n");
		}

		/*
    int fd1 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		char buf[8192];
		while(read(fd1, buf, 8192)>0)
		printf("%s\n",buf);//+sizeof(struct iphdr)+sizeof(struct tcphdr));
   */

		return 0;
}