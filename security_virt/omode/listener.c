#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <rohc/rohc.h>
#include <rohc/rohc_decomp.h>
#include <rohc/rohc_time.h>

#define FEEDBACKPORT "3495"
#define LISTENPORT "3490"
#define BUFFER_SIZE 2048
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

struct rohc_decomp *decompressor;       /* the ROHC decompressor */

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
	void
print_hex_ascii_line(const u_char *payload, int len, int offset)
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

/*
 * print packet payload data (avoid printing binary data)
 */
	void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
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

void send_feedback(struct rohc_buf feedback,int actual){
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	char *address = "192.168.0.100";

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(address, FEEDBACKPORT, &hints, &servinfo)) != 0) {
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

	char message[1000] = {};
	size_t i;
	for(i = 0; i < feedback.len; i++)
	{
		message[i] = rohc_buf_byte_at(feedback, i);

	}
	if (actual && ((numbytes = sendto(sockfd, message, feedback.len, 0,
						p->ai_addr, p->ai_addrlen)) == -1)) {
		perror("CompressorSend: sendto");
		exit(1);
	}
	if(!actual){
		/*If there is no feedback to send, send this to indicate*/
		message[0] = 0x1f;
		message[1] = 0x2f;
		numbytes = sendto(sockfd, message, 2, 0, p->ai_addr,p->ai_addrlen);
		if(numbytes == -1){
			perror("SendFeedback: Emptymarker");
			exit(1);
		}
	}
	freeaddrinfo(servinfo);
	close(sockfd);
	printf("-----------------------\n");
	printf("Sent a feedback of length: %d\n",feedback.len);
	if(actual)
		print_payload(message, feedback.len);
	else
		print_payload(message,2);
	printf("-----------------------\n");
}

void CreateDecompressor(){
	printf("\ncreate the ROHC decompressor\n");
	/*Remember to create the decompressor exact to the compressor
	  Prothome chorachillam
	 */
	decompressor = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE);
	if(decompressor == NULL)
	{
		fprintf(stderr, "failed create the ROHC decompressor\n");
		goto error;
	}
	/* Enable the decompression profiles you need */
	printf("\nenable several ROHC decompression profiles\n");
	if(!rohc_decomp_enable_profile(decompressor, ROHC_PROFILE_UNCOMPRESSED))
	{
		fprintf(stderr, "failed to enable the Uncompressed profile\n");
		goto release_decompressor;
	}
	if(!rohc_decomp_enable_profile(decompressor, ROHC_PROFILE_IP))
	{
		fprintf(stderr, "failed to enable the IP-only profile\n");
		goto release_decompressor;
	}
	if(!rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP,
				ROHC_PROFILE_UDPLITE, -1))
	{
		fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite "
				"profiles\n");
		goto release_decompressor;
	}

	return;
release_decompressor:
	rohc_decomp_free(decompressor);
error:
	fprintf(stderr, "an error occured during program execution, "
			"abort program\n");
	exit(1);


}

int DecompressPacket(const char *payload, int size_payload){
	printf("Attempting to Decompress, IN O_MODE\n");

	/*Fill the rohc buffer with recieved compressed packet*/
	struct rohc_ts arrival_time = 
	{.sec = 0,
		.nsec = 0};
	struct rohc_buf rohc_packet = rohc_buf_init_full(payload,
			size_payload,
			arrival_time);

	size_t i;

	/* the buffer that will contain the resulting IP packet */
	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);

	/* we Do not want to handle feedback this time */
	unsigned char rcvd_feedback_buffer[BUFFER_SIZE];
	unsigned char feedback_send_buffer[BUFFER_SIZE];
	struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcvd_feedback_buffer,BUFFER_SIZE);
	struct rohc_buf feedback_send = rohc_buf_init_empty(feedback_send_buffer,BUFFER_SIZE);

	rohc_status_t status;


	/*Decompression starts here*/
	printf("\ndecompress the fake ROHC packet\n");
	//! [decompress ROHC packet #1]
	status = rohc_decompress3(decompressor, rohc_packet, &ip_packet,
			&rcvd_feedback, &feedback_send);
	if(status == ROHC_STATUS_OK)
	{
		/* decompression is successful */
		if(!rohc_buf_is_empty(ip_packet))
		{
			/* ip_packet.len bytes of decompressed IP data available in
			 * ip_packet: dump the IP packet on the standard output */
			printf("IP packet resulted from the ROHC decompression:\n");
		}
		else
			printf("no IP packet decompressed");

		if(!rohc_buf_is_empty(feedback_send)){
			printf("YOYOYOYO WE GOT ONE FRESHLY BAKED FEEDBACK\n");
			send_feedback(feedback_send,1);	
		}
		else{
			printf("NO FEEDBACK TO SEND, WHATDO?\n");
			send_feedback(feedback_send,0);
		}
	}
	else
	{
		/* failure: decompressor failed to decompress the ROHC packet */
		fprintf(stderr, "decompression of fake ROHC packet failed\n");
		//! [decompress ROHC packet #2]
		goto release_decompressor;
		//! [decompress ROHC packet #3]
	}

	return 0;

release_decompressor:
	rohc_decomp_free(decompressor);
error:
	fprintf(stderr, "an error occured during program execution, "
			"abort program\n");
	return 1;

}

void Listen(){
	printf("Listening for packet\n");
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

	if ((rv = getaddrinfo(NULL, LISTENPORT, &hints, &servinfo)) != 0) {
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
	DecompressPacket(buf,numbytes);
	close(sockfd);
}

int main(int argc, char **argv)
{
	CreateDecompressor();
	while(1)
		Listen();	
	printf("Exiting Listener...\n");
	return 0;
}

