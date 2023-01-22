# include "mylib.hpp"

// dumps raw memory in hex byte and printable split format
void mySock::dump(const unsigned char *data_buffer, const unsigned int length)
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

unsigned short mySock::in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register unsigned short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *) & oddbyte) = *(unsigned char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}



int	mySock::createSocket(char *srcIp , char *destIp)
{	

	int payload_size = 0, sent, sent_size;


	this->saddr = inet_addr(srcIp);
	this->daddr = inet_addr(destIp);

	//Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
	this->sockFd = socket (AF_PACKET, SOCK_RAW, htons(0x0800));
	
	if (this->sockFd < 0) 
	{
		perror("could not create socket");
		exit(-1);
	}
	
	int on = 1;
	
	// We shall provide IP headers
	/*
	if (setsockopt (this->sockFd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		exit(-1);
	}*/
	
	//allow socket to send datagrams to broadcast addresses
	/*
	if (setsockopt (this->sockFd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}
	*/



	return (this->sockFd);
}

void	mySock::setData(char *data)
{




	int	dataSize;
	unsigned int	counter;
	size_t sent_size;
	dataSize = strlen(data);

	//Calculate total packet size
	int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + dataSize;
	char *packet = (char *) malloc (packet_size);

	if (!packet) 
	{
		perror("out of memory");
		close(this->sockFd);
		exit(-1);
	}
	
	//ip header
	struct iphdr *ip = (struct iphdr *) packet;
	struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
	
	//zero out the packet buffer
	memset (packet, 0, packet_size);

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons (packet_size);
	ip->id = rand ();
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = this->saddr;
	ip->daddr = this->daddr;
	ip->check = in_cksum ((unsigned short *) ip, sizeof (struct iphdr));

  	icmp->type = ICMP_ECHO;
	icmp->code = 0;
  	icmp->un.echo.sequence = htons(0);
  	//icmp->un.echo.id = rand();
  	//checksum
	icmp->checksum = 0;
	
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

	counter = 0;
	while (counter < dataSize)
	{
		*(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) + counter) = *(data + counter);
		counter++;
	}


	//recalculate the icmp header checksum since we are filling the payload with random characters everytime
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + dataSize);



	struct ifreq deneme;
	int		ifindex;
  	char *iface = "wlp0s20f3";

	memset(&deneme, 0, sizeof(deneme));

	strncpy(deneme.ifr_name, iface, IFNAMSIZ);
	if (ioctl(this->sockFd, SIOCGIFINDEX, &deneme) < 0) {
		printf("Error: could not get interface index\n");
		close(this->sockFd);
		exit -1;
	}
	ifindex = deneme.ifr_ifindex;
	
	unsigned char source[ETH_ALEN];
	if (ioctl(this->sockFd, SIOCGIFHWADDR, &deneme) < 0) {
		printf("Error: could not get interface address\n");
		close(this->sockFd);
		exit -1;
	}
	//deneme.ifr_hwaddr.sa_data[0] = 0xdd;
	memcpy((void*)source, (void*)(deneme.ifr_hwaddr.sa_data),
			ETH_ALEN);
	

	unsigned char dest[ETH_ALEN]
           = { 0xd0, 0x88, 0x0c, 0x74, 0xfa, 0x94 };
	unsigned short proto = 0x0800;
	union ethframe frame;
	memcpy(frame.field.header.h_dest, dest, ETH_ALEN);
	memcpy(frame.field.header.h_source, source, ETH_ALEN);
	frame.field.header.h_proto = htons(proto);
	memcpy(frame.field.data, packet, packet_size);


	unsigned int frame_len = packet_size + ETH_HLEN;
 
 /*
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
*/

	struct sockaddr_ll saddrll;
	memset((void*)&saddrll, 0, sizeof(saddrll));
	saddrll.sll_family = PF_PACKET;   
	saddrll.sll_ifindex = ifindex;
	saddrll.sll_halen = ETH_ALEN;
	saddrll.sll_protocol = IPPROTO_ICMP;
	memcpy((void*)(saddrll.sll_addr), (void*)dest, ETH_ALEN);

	if (sendto(this->sockFd, frame.buffer, frame_len, 0, (struct sockaddr*)&saddrll, sizeof(saddrll)) > 0)
		printf("Success!\n");
	else
		printf("Error, could not send\n");



	/*
	if ( (sent_size = sendto(this->sockFd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
	{
		perror("send failed\n");
	}
	*/
	free(packet);
	close(this->sockFd);
}

void	mySock::catchResponse()
{
		sockaddr_in client;

		struct sockaddr_ll saddrll;
		socklen_t clientSockLen = sizeof(saddrll);
		char packet[4096];
		int	rc;

		int receive_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(receive_s < 0)
		{
			std::cout << "Receive Socket Err!" << std::endl << std::flush;
			exit(-1);
		}

		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (setsockopt(receive_s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof (tv)) < 0)
		{
			std::cout << "SetSockOpt RCVTIMEO Err!" << std::endl << std::flush;
			close(receive_s);
			exit(-1);
		}

		rc = recvfrom(receive_s, packet, sizeof(packet), 0, (struct sockaddr *)&saddrll, &clientSockLen);
		if (rc < 0)
		{
			std::cout << "Recv Error!" << std::endl << std::flush;
			close(receive_s);
			exit(-1);
		}
		close(receive_s);
		packet[rc] = 0;


		std::cout << "Okunan byte= " << rc << std::endl << "Client Sock Len= " << sizeof(client)  << std::endl << std::flush;

		std::cout << saddrll.sll_addr << std::endl << std::flush;
		std::cout << saddrll.sll_protocol << std::endl << std::flush;

		//printf("\n%d\n", client.sin_family);
		//printf("\n%s\n", client.sin_zero);
		
		//printf("%s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
		//printf("accept request, fd is %d, pid is %d\n", listenchannel, getpid());

		char newcraft[4096];

		memset(newcraft, 0, 4096);


		memcpy(newcraft, &client, sizeof(client));
		memcpy(newcraft + sizeof(client), packet, rc);

		dump((unsigned char *)newcraft, sizeof(client) + rc);
		//write(1, packet, rc);
		//write(1, "\n", 1);
}