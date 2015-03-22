/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
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

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

int main(void)
{
	int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);    
	if(sd<=0){
		printf("Error: Could not open socket\n");
		return 1;
	}

	int broadcastEnable = 1;
	int ret = setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
	if(ret){
		printf("Error: Could not open set socket to broadcast mode");
		close(sd);
		return 1;
	}

	struct sockaddr_in broadcastAddr; //Make an endpoint
	memset(&broadcastAddr,0,sizeof broadcastAddr);
	broadcastAddr.sin_family = AF_INET;
	inet_pton(AF_INET, "239.255.255.250", &broadcastAddr.sin_addr);
	broadcastAddr.sin_port = htons(3490); 

	char *request = "Is there anybody out there?";
	ret = sendto(sd, request, strlen(request),0,(struct sockaddr*)&broadcastAddr, sizeof broadcastAddr);
	if(ret<0){
		printf("Could not open send broadcast");
		close(sd);
		return 1;
	}

	close(sd);

    return 0;
}
