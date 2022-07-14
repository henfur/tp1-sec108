/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <arpa/inet.h>

#define MAXDATASIZE 1024 // max number of bytes we can get at once 

#define SERVICES_PATH "/etc/services"

struct service
{
	char port[8];
	char svc_name[32];
	int protocol; // 0 -> TCP, 1 -> UDP
	int state; // 0 -> CLOSED, 1 -> OPEN
} service;


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * @brief Get the service port and name mapping using /etc/services on UNIX systems
 * 
 * @param svc_list list of services (struct service)
 * @param start_port start of port range given by user
 * @param end_port end of port range given by user
 * @return int: 0 if terminated succesfully, EXIT_FAILURE if file could not be opened
 */
int get_svc_list(struct service *svc_list, int start_port, int end_port) {
	char line[128];
	char patern[128];
	for(int i = (start_port - 1) ; i < end_port ; i++) {

		FILE *services_file = fopen(SERVICES_PATH,"r");
	
		if (!services_file) {
			perror("fopen");
			return EXIT_FAILURE;
		}

		struct service *svc = malloc(sizeof(struct service));
		sprintf(svc->port, "%d", i+1);

		strcpy(patern," ");
		strcat(patern, svc->port);
		strcat(patern, "/tcp");
		int found = 0;
		while (fgets(line, sizeof(line), services_file) != NULL) {
			if(strstr(line, patern)) {
				int index = 0;
				while(line[index] != ' ' && index < sizeof(svc)) {
					svc->svc_name[index] = line[index];
					index++;
				}
				svc->svc_name[index] = '\0';
				found = 1;
				break;
			}
		}
		if (found == 0) {
			strcpy(svc->svc_name, "unknown");
		}

		svc_list[i] = *svc;
		close(services_file);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	int port_start_range, port_end_range;
	char port[8];

	if (argc < 2) {
	    fprintf(stderr,"usage: client hostname port_start port_end\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int start_port = atoi(argv[2]);
	int end_port = atoi(argv[3]);

	struct service *svc_list = malloc((atoi(argv[3]) - atoi(argv[2])) * sizeof(struct service));

	get_svc_list(svc_list, atoi(argv[2]), atoi(argv[3]));

	int current_port;
	for (current_port = atoi(argv[2]) ; current_port <= atoi(argv[3]) ; current_port++) {

		if ((rv = getaddrinfo(argv[1], svc_list[current_port - 1].port, &hints, &servinfo)) != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
			return 1;
		}

		// loop through all the results and connect to the first we can
		// for(p = servinfo; p != NULL; p = p->ai_next) {
		p = servinfo;
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		// fcntl(sockfd, F_SETFL, O_NONBLOCK);

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			// perror("client: connect");
			svc_list[current_port - 1].state = 0;
			close(sockfd);
			continue;
		} else {
			svc_list[current_port - 1].state = 1;
		}

		if (p == NULL) {
			fprintf(stderr, "client: failed to connect\n");
			return 2;
		}

		inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
				s, sizeof s);
		printf("client: connecting to %s\n", s);

		freeaddrinfo(servinfo); // all done with this structure

		if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
			perror("recv");
			exit(1);
		}

		buf[numbytes] = '\0';

		printf("client: received %s\n",buf);
		
		// printf("nb svc list: %d\n", sizeof(svc_list));
		// printf("size of svc: %d\n", sizeof(service));

		close(sockfd);
	}

	printf("SEC108 TP1 - PORT SCANNER in C\n===========================================================\nPORT\tSTATE\tSERVICE\t\n");

	for(int i = 0 ; i <= atoi(argv[3]) ; i++) {
		if(svc_list[i].state == 1) {
			printf("%s\topen\t%s\n", svc_list[i].port, svc_list[i].svc_name);
		}
	}

	return 0;
}

