#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/ip_icmp.h>


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


int main()
{
		// receiver socket // PF or AF_INET doesnt matter 
		// IPPROTO_RAW is 255 unknown protocol and dont get a response
		int receive_s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		u_char buffer[1500];
		struct sockaddr_in sin;
		socklen_t sinlen = sizeof(sin);		


		while(1)
		{
			// int ret = recv(receive_s, &buffer, sizeof(buffer), 0);
			int ret = recvfrom(receive_s, &buffer, sizeof(buffer), 0, (struct sockaddr *)&sin, &sinlen);

			fprintf(stdout, "\n\nRECV %d BYTES\n", ret);
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

		// close(receive_s);
		
	return 0;
}