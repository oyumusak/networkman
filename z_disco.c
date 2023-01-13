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

// Subnet Calculator
#include <ctype.h>					// isprint() and isdigit()
#include <math.h>						// pow()

int ipVerify(char* ipAddress, unsigned char* octetArray) 
{
	// Function verifies a valid IP has been entered, and then updates the octal array with the validated octets

	char* token;
	int i = 0;
	int j = 0;
	int periodCount = 0;

	// We will continue grabbing tokens whilst it isn't null
	token = strtok(ipAddress, ".");
	while (token != NULL) 
	{
		// Loop through each character and check it's a digit
		// If it isn't break out. We use j to see if it looped the right amount of times
		for (j=0; j<strlen(token); j++) {
			if (isdigit(token[j]) == 0) {
				break;
			}
		}

		// If the right amount of digits have been entered, confirm octet as validated and add to array
		if (strlen(token) > 0 && strlen(token) < 4 && j == strlen(token)
				&& atoi(token) < 256 && atoi(token) >= 0) 
		{
			periodCount++;
			octetArray[i] = atoi(token);
		} else { break; }
		i++;
		token = strtok(NULL, ".");
	}
	if (periodCount != 4) { return 0; } 
	else { return 1; }
}

void printSubnetInfo(u_int32_t* addressOctets, int* CIDR, int* subnetBits) 
{
	// Prints infomation about the given subnet.
	// Takes pointers to the required data, however does not change anything within them.
	// Any required manipulation is done with local variables

	u_int32_t netAddress;
	u_int32_t netMask;
	
	netMask = (0xFFFFFFFF << (32 - (*CIDR + *subnetBits)) & 0xFFFFFFFF);
	netAddress = *addressOctets & netMask;

	// Unpack and display the network address
	printf("\nNetwork address: %d.%d.%d.%d/%d\n", (netAddress >> 24) & 0xFF, (netAddress >> 16) & 0xFF,
						    (netAddress >> 8) & 0xFF, (netAddress) & 0xFF, *CIDR + *subnetBits);

	// Subtract the network address from the broadcast address and take one from the result for total hosts
	printf("Total hosts: %d\n", ((netAddress | ~netMask) - netAddress) - 1);

	// Display the first host address by adding to each of our unpacked octets
	printf("First host address: %d.%d.%d.%d\n", ((netAddress + 1) >> 24) & 0xFF, ((netAddress + 1) >> 16) & 0xFF,
						    ((netAddress + 1) >> 8) & 0xFF, (netAddress + 1) & 0xFF);
	
	// Bitwise OR the address int with the negated mask to get the broadcast address in the variable
	netAddress = netAddress | ~netMask;

	// Subtract from the from the broadcast address for the final host address
	printf("Last host address: %d.%d.%d.%d\n", ((netAddress - 1) >> 24) & 0xFF, ((netAddress - 1) >> 16) & 0xFF,
						   ((netAddress - 1) >> 8) & 0xFF, (netAddress - 1) & 0xFF);
	
	// Unpack and display the broadcast address
	printf("Broadcast address: %d.%d.%d.%d\n", (netAddress >> 24) & 0xFF, (netAddress >> 16) & 0xFF,
						   (netAddress >> 8) & 0xFF, (netAddress) & 0xFF);
}

int subcalc() 
{
	char ipAddress[18];
	char buffer[4];
	int CIDR;
	unsigned char* octetArray;
	// void * malloc to allow for casting to unsigned char* later
	
	octetArray = (unsigned char*) malloc(4 * sizeof(unsigned char));
	u_int32_t addressOctets;
	
	int subnetNumber;
	int subnetBits = 0;
	int totalSubnets = 0;
	u_int32_t currentSubnet;
	int i;

	// Get the address
	while (1) {
		printf("Enter IPv4 address now: ");
		fgets(ipAddress, 17, stdin);
		ipAddress[strlen(ipAddress)-1] = '\0';

		printf("Verifying: %s... ", ipAddress);

		// Verify it
		if (ipVerify(ipAddress, octetArray) == 0) {
			printf("Invalid IP entered.\n");
		} else {
			printf("Address verified!\n");
			break;
		}
	}

	// Get the CIDR number
	while (1) {
		printf("Enter subnet mask in CIDR notation now: ");
		fgets(buffer, 4, stdin);

		CIDR = atoi(buffer);

		if (CIDR > 0 && CIDR < 32) {
			break;
		} else {
			printf("Invalid CIDR entered. Try again.\n");
		}
	}

	printf("\n%d.%d.%d.%d/%d ", octetArray[0], octetArray[1], octetArray[2], octetArray[3], CIDR);

	if (octetArray[0] > 239) {
		printf("(Class E)\n");
	} else if (octetArray[0] > 223) {
		printf("(Class D)\n");
	} else  if (octetArray[0] > 191) {
		printf("(Class C)\n");
	} else if (octetArray[0] > 127) {
		printf("(Class B)\n");
	} else {
		printf("(Class A)\n");
	}

	// Pack bits of the IP address into an integer
	addressOctets = (octetArray[0] << 24) | (octetArray[1] << 16) | (octetArray[2] << 8) | (octetArray[3]);

	// Call the subnetinfo function for the network
	printSubnetInfo(&addressOctets, &CIDR, &subnetBits);

	do {
		printf("Enter number of required networks, or q to quit: ");
		fgets(buffer, 4, stdin);
		subnetNumber = atoi(buffer);

		if (subnetNumber == 0) {
			printf("Exiting...\n");
			exit(0);
		}

		// Determine the amount of bits required to contain the required networks
		while (subnetNumber > totalSubnets) {
			subnetBits++;
			totalSubnets = pow(2, subnetBits);
		}

		// Check we have the required amount of bits to subnet successfully
		if ((CIDR + subnetBits) > 31) {
			printf("Amount of networks too large to be accommodated.\n");
		}
	} while ((CIDR + subnetBits) > 31);

	printf("\nTotal subnets to be created: %d\n-------------------------------", totalSubnets); 

	// Construct the subnet network bits, then print the information
	for (i=0; i<totalSubnets; i++) {
		currentSubnet = (addressOctets & ((0xFFFFFFFF << (32 - CIDR)) & 0xFFFFFFFF))
				| i << (32 - (CIDR + subnetBits));
		printSubnetInfo(&currentSubnet, &CIDR, &subnetBits);
	}

	free(octetArray);
	
	return 0;
}








/* this is a simple ICMP network discovery program */
// sudo tcpdump -i any host 192.168.1.117 and host 8.8.8.8

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


void subnet_to_ip_list(char *subnet, char ip_list[255][16])
{
	char *pch;
	char *ip;
	char *mask;
	char *ip_mask[2];
	int i = 0;

	pch = strtok(subnet, "/");
	while (pch != NULL)
	{
		ip_mask[i] = pch;
		pch = strtok(NULL, "/");
		i++;
	}

	ip = ip_mask[0];
	mask = ip_mask[1];

	int mask_int = atoi(mask);
	int mask_bit = 0;
	for (int i = 0; i < mask_int; i++)
		mask_bit += pow(2, 31 - i);

	int ip_int = inet_addr(ip);
	int ip_mask_int = ip_int & mask_bit;

	for (int i = 0; i < 255; i++)
	{
		int ip_int = ip_mask_int + i;
		struct in_addr ip_addr;
		ip_addr.s_addr = ip_int;
		strcpy(ip_list[i], inet_ntoa(ip_addr));
	}
}


int main(int argc, char *argv[])
{
	// call subcalc to get ip list from subnet address and mask 
	subcalc();

	int transmit_s, receive_s, rc, ret;
	struct protoent *p;
	struct sockaddr_in sin;
	struct ip ip;
	struct icmp icmp;

	if (argc != 3)
		errx(EX_USAGE, "Usage: %s <source_addr> <subnet_addr>", argv[0]);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;

	/* Parse source address. */
	if (inet_pton(AF_INET, argv[1], &sin.sin_addr) <= 0)
		err(EX_USAGE, "Parse address");

	/* subnet to ip list */
	char ip_list[255][16];
	subnet_to_ip_list(argv[2], ip_list);
	// print ip_list
	for (int i = 0; i < sizeof(ip_list) / sizeof(ip_list[0]); i++)
		printf("%s\n", ip_list[i]);
	printf(" %d ", sizeof(ip_list) / sizeof(ip_list[0]));


	// length of ip_list
	int ip_list_len = sizeof(ip_list) / sizeof(ip_list[0]);

	for (int i = 0; i < ip_list_len; i++)
	{

		/* Parse destination address. */
		if (inet_pton(AF_INET, ip_list[i], &sin.sin_addr) <= 0)
			err(EX_USAGE, "Parse address %s", ip_list[i]);

		transmit_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (transmit_s < 0)
			err(EX_OSERR, "error open transmit_s raw socket on %s to %s", argv[0], argv[2]);

		int one = 1;
		const int *val = &one;
		if (setsockopt(transmit_s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{ perror("setsockopt() IP_HDRINCL error"); exit(-1); }

		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(transmit_s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

		/* Fill in the ICMP header. */
		memset(&icmp, 0x0, sizeof(icmp));
		icmp.icmp_type = ICMP_ECHO;
		icmp.icmp_code = 0;
		icmp.icmp_cksum = 0;
		icmp.icmp_id = htons(getpid());
		icmp.icmp_seq = htons(i); // sequence number for dummy ping packet is i
		icmp.icmp_cksum = cksum((unsigned short *)&icmp, sizeof(icmp));

		/* IP header */
		ip.ip_hl = 5;
		ip.ip_v = 4;
		ip.ip_tos = IPTOS_MINCOST;
		ip.ip_len = sizeof(struct ip) + sizeof(struct icmp);
		ip.ip_id = htons(getpid());
		ip.ip_off = 0;
		ip.ip_ttl = MAXTTL;
		ip.ip_p = IPPROTO_ICMP;
		ip.ip_sum = 0;
		ip.ip_src.s_addr = inet_addr(argv[1]);
		ip.ip_dst.s_addr = inet_addr(argv[2]);
		ip.ip_sum = cksum((unsigned short *)&ip, sizeof(ip));

		/* packet */
		u_char packet[4096];
		memcpy(packet, &ip, sizeof(ip));
		memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));

		/* Send the request. */
		rc = sendto(transmit_s, packet, ip.ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) { err(EX_OSERR, "error sendto sendlen=%d error no = %d\n", rc, errno); }

		fprintf(stdout, "\n  SENT %d BYTES\n", ip.ip_len);
		fprintf(stdout, "-----------------\n");
		fprintf(stdout, "ID\t: %d\n", ntohs(icmp.icmp_id));
		fprintf(stdout, "Src\t: %s\n", inet_ntoa(ip.ip_src));
		fprintf(stdout, "Dest\t: %s\n", inet_ntoa(ip.ip_dst));
		fprintf(stdout, "Type\t: %d\n", icmp.icmp_type);
		fprintf(stdout, "Code\t: %d\n", icmp.icmp_code);
		fprintf(stdout, "Seq\t: %d\n", htons(icmp.icmp_seq));
		fprintf(stdout, "TTL\t: %d\n", ip.ip_ttl);
		close(transmit_s);
		
		/* Receive the response. */
		receive_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		u_char buffer[4096];
		socklen_t sinlen = sizeof(sin);

		struct ip *ip_recv = (struct ip *)buffer;
		struct icmp *icmp_recv = (struct icmp *)(buffer + (ip_recv->ip_hl << 2));
		memcpy(buffer, &ip_recv, sizeof(ip_recv));
		memcpy(buffer + sizeof(ip_recv), &icmp_recv, sizeof(icmp_recv));

		ret = recvfrom(receive_s, buffer, sizeof(buffer), 0, (struct sockaddr *)&sin, &sinlen);

		fprintf(stdout, "\n  RECV %d BYTES\n", rc);
		fprintf(stdout, "-----------------\n");
		fprintf(stdout, "ID\t: %d\n", ntohs(icmp_recv->icmp_id));
		fprintf(stdout, "Src\t: %s\n", inet_ntoa(ip_recv->ip_src));
		fprintf(stdout, "Dst\t: %s\n", inet_ntoa(ip_recv->ip_dst));
		fprintf(stdout, "Type\t: %d\n", icmp_recv->icmp_type);
		fprintf(stdout, "Code\t: %d\n", icmp_recv->icmp_code);
		fprintf(stdout, "Seq\t: %d\n", htons(icmp_recv->icmp_seq));
		fprintf(stdout, "TTL\t: %d\n", ip_recv->ip_ttl);
		fprintf(stdout, "Hops\t: %d\n", MAXTTL - ip_recv->ip_ttl);
		close(receive_s);
		
	}
	return 0;
}