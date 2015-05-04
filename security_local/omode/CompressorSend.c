#include <stdio.h>  
#include <ctype.h>
#include <netinet/ip.h>  
#include <rohc/rohc_buf.h>  
#include <time.h>             
#include <rohc/rohc_comp.h>   
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define BUFFER_SIZE 2048
#define FAKE_PAYLOAD "hello, ROHC world!"

#define PORT "3490"  // the port users will be connecting to
#define FEEDBACKPORT "3495"
#define BACKLOG 10     // how many pending connections queue will hold

/* return a random number every time it is called */
static int gen_random_num(const struct rohc_comp *const comp,
		void *const user_context)
{
	return rand();
}

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int iterator = 10;

struct Message{
	char *content;
	int length;
};

struct rohc_comp *compressor;  /* the ROHC compressor */

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");

	return;
}



void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;                    /* number of bytes per line */
	int line_len;
	int offset = 0;                                 /* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


void CreateCompressor(){
	/* create a ROHC compressor with good default parameters */
	printf("create the ROHC compressor\n");
	compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
			gen_random_num, NULL);
	if(compressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC compressor\n");
		/* leave with an error code */
		exit(1);
	}

	/* enable the IP-only compression profile */
	printf("enable the IP-only compression profile\n");
	if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
	{
		fprintf(stderr, "failed to enable the IP-only profile\n");
		/* cleanup compressor, then leave with an error code */
		rohc_comp_free(compressor);
		exit(1);
	}
}

struct Message CompressPacket()
{
	/* the buffer that will contain the IPv4 packet to compress */
	uint8_t ip_buffer[BUFFER_SIZE];
	/* the packet that will contain the IPv4 packet to compress */
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	/* the header of the IPv4 packet */
	struct iphdr *ip_header;

	uint8_t rohc_buffer[BUFFER_SIZE];
	/* the packet that will contain the resulting ROHC packet */
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);

	rohc_status_t rohc_status;
	size_t i;

	/* print the purpose of the program on the console */
	printf("Will compress one single IPv4 packet and broadcast it\n");

	/* initialize the random generator with the current time */
	srand(time(NULL));

	/* create a fake IP packet for the purpose of this simple program */
	printf("build a fake IP packet\n");
	ip_header = (struct iphdr *) rohc_buf_data(ip_packet);
	ip_header->version = 4; /* we create an IP header version 4 */
	ip_header->ihl = 5; /* min. IPv4 header length (in 32-bit words) */
	ip_packet.len += ip_header->ihl * 4;
	ip_header->tos = 0; /* TOS is not important for the example */
	ip_header->tot_len = htons(ip_packet.len + strlen(FAKE_PAYLOAD));
	ip_header->id = 0; /* ID is not important for the example */
	ip_header->frag_off = 0; /* No packet fragmentation */
	ip_header->ttl = 1; /* TTL is not important for the example */
	ip_header->protocol = 134; /* protocol number */
	ip_header->check = 0x3fa9; /* checksum */
   ip_header->saddr = htonl(0x01020304); /* source address 1.2.3.4 */
	ip_header->daddr = htonl(0x05060708); /* destination addr. 5.6.7.8 */


	/* copy the payload just after the IP header */
	rohc_buf_append(&ip_packet, (uint8_t *) FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));

	/* compress the fake IP packet */
	printf("compress the fake IP packet\n");
	rohc_status = rohc_compress4(compressor, ip_packet, &rohc_packet);
	if(rohc_status != ROHC_STATUS_OK)
	{
		fprintf(stderr, "compression of fake IP packet failed: %s (%d)\n",
				rohc_strerror(rohc_status), rohc_status);
		/* cleanup compressor, then leave with an error code */
		rohc_comp_free(compressor);
		exit(1);
	}

	/* dump the ROHC packet in a char arrary*/

	char *m = (char *)malloc(rohc_packet.len);
	for(i = 0; i < rohc_packet.len; i++)
	{
		m[i] = rohc_buf_byte_at(rohc_packet,i);
	}
	struct Message out;
	out.content = m;
	out.length = rohc_packet.len;

	printf("destroy the ROHC compressor\n");
	return out;
}

void SendAPacket(char *address){
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(address, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "CompressPacket: failed to bind socket\n");
		exit(1);
	}
	struct Message in = CompressPacket();
   // if(iterator == 5){
   //    printf("******************\n");
   //    in.content[0] = 0xf3;
   // }

	if ((numbytes = sendto(sockfd, in.content, in.length, 0,
					p->ai_addr, p->ai_addrlen)) == -1) {
		perror("CompressorSend: sendto");
		exit(1);
	}

	freeaddrinfo(servinfo);
	close(sockfd);
	printf("-----------------------\n");
	printf("Sent a packet\n");

}

void ReceiveFeedback(){
	printf("Waiting for feedback\n");
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	struct sockaddr_storage their_addr;
	char buf[BUFFER_SIZE];
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, FEEDBACKPORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		exit(1);
	}

	freeaddrinfo(servinfo);

	printf("listener: waiting to recvfrom...\n");

	addr_len = sizeof their_addr;
	if ((numbytes = recvfrom(sockfd, buf, BUFFER_SIZE-1 , 0,
					(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		perror("recvfrom");
		exit(1);
	}

	printf("listener: got packet from %s\n",
			inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s, sizeof s));
	printf("listener: packet is %d bytes long\n", numbytes);

	print_payload(buf,numbytes);
	printf("---------------\n");
	close(sockfd);
   if(buf[0] == 0x1f && buf[1] == 0x2f)
      printf("BOOO: NO FEEDBACK THIS TIME\n");
   else{
      struct rohc_ts arrival_time = {
         .sec = 0,
         .nsec = 0
      };
      const struct rohc_buf feedback = rohc_buf_init_full(buf,numbytes,arrival_time);
      if(rohc_comp_deliver_feedback2(compressor,feedback))
         printf("Feedback successfully delivered\n");
      else
         printf("Feedback unsuccessfully delivered\n");
   }
	char pop[200];
	scanf("%s",pop);
}


int main(int argc, char **argv)
{  
	if(argc != 2){
		printf("USAGE: CompressorSend Address\n");
		return 1;
	}

	char *address = (char *)malloc(32);
	strcpy(address,argv[1]);

	CreateCompressor();
	
	while(iterator--){
      if(iterator==5)
         SendAPacket(address); //This will be a malformed packet
		SendAPacket(address);
		ReceiveFeedback();
	}

	printf("END\n");
	rohc_comp_free(compressor);
	return 0;
}
