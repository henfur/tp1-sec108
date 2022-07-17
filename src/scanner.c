/*
** SEC108 - TP1 - PORT SCANNER
** Author: Amaury JASPAR
** Base file from: https://beej.us/guide/bgnet/examples/client.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pthread.h>

#include <arpa/inet.h>

#define SERVICES_PATH "/etc/services"

struct service
{
	char port[8];
	char svc_name[32];
	int state; // 0 -> CLOSED, 1 -> OPEN
};

struct scan_args {
	struct service *svc_list;
	char *hostname;
	int start_port;
	int end_port;
	struct addrinfo hints;
};


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
	int port;

	FILE *services_file = fopen(SERVICES_PATH,"r");

	if (!services_file) {
		perror("fopen");
		return EXIT_FAILURE;
	}
	
	// Bulding initial service/port map with default "unknown" svc_name
	for(int j = 0 ; j < ((end_port - start_port) + 1) ; j++) {
		struct service *svc = malloc(sizeof(struct service));
		sprintf(svc->port, "%d", start_port + j);
		strcpy(svc->svc_name, "unknown");
		svc_list[j] = *svc;
	}

	/**
	 * @brief Parsing the services file
	 * SVC name is recovered at the beginning of the line
	 * The port written on the current line is then checked against the given port range,
	 * if the port is higher than the current range, the loop terminates, if it is smaller
	 * the current iteration is skipped
	 * 
	 * A better approach might be to start at the end of the line to get the port number first
	 * and check immediatly if it matches. But given the number of lines, it seems to have little impact
	 * on performance
	 */
	char  line_port[8];
	char  line_svc_name[32];
	int p_index;
	fgets(line, sizeof(line), services_file);
	while (fgets(line, sizeof(line), services_file) != NULL) {
		if(! strstr(line, "/tcp")) continue;

		p_index = 0;

		while(
			line[p_index] != ' ' &&
			line[p_index] != '\t' &&
			p_index < 128
		) {
			line_svc_name[p_index] = line[p_index];
			p_index++;
		}
		line_svc_name[p_index] = '\0';

		p_index++;
		int port_start_index = p_index;

		while(line[p_index] != '/') {
			if(line[p_index] != ' ' && line[p_index] != '\t') {
				line_port[p_index - port_start_index] = line[p_index];
			} else {
				port_start_index++;
			}
			p_index++;
		}
		line_port[p_index - port_start_index] = '\0';
		port = atoi(line_port);

		if (port >= start_port && port <= end_port) {
			strcpy(svc_list[port - start_port].svc_name, line_svc_name);
		} else if (port > end_port) {
			break;
		}
	}
	close(services_file);
	return 0;
}

/**
 * @brief displays port scan results to stdout
 * 
 * @param svc_list list of scanned services
 * @param start start of port range
 * @param end end of port range
 * @return void* 
 */
void *display(struct service *svc_list, int start, int end) {
	int choice = 1;

	while(choice != 0) {
		printf(
			"\033[34;1mSEC108 TP1 - PORT SCANNER in C\033[0m\n"
			"===============================\n"
			"[1]\tShow only \033[92;1mopened\033[0m ports\n"
			"[2]\tShow only \033[31;1mclosed\033[0m ports\n"
			"[3]\tShow only all results (\033[4mWarning\033[0m: can be quite a long output depending on your port range\n"
		);

		printf("Choice: ");
		scanf("%d", &choice);

		printf(
			"\n"
			"PORT\tSTATE\tSERVICE\n"
			"-----------------------\n"
		);

		for(int i = 0 ; i < ((end - start) + 1) ; i++) {
			char state_string[8];
			if (svc_list[i].state == 1 && choice != 2) {
				printf("%s\t\033[92;1mopened\033[0m\t%s\n", svc_list[i].port, svc_list[i].svc_name);
			} else if (choice != 1) {
				printf("%s\t\033[31;1mclosed\033[0m\t%s\n", svc_list[i].port, svc_list[i].svc_name);
			} 
		}

		printf(
			"\n"
			"[4]\tGo back to menu\n"
			"[0]\tExit the program\n\n"
		);
		printf("Choice: ");
		scanf("%d", &choice);
		if(choice != 4 && choice != 0) {
			fprintf(stderr, "ERROR: Unexpected input");
			exit(1);
		}
	}
}


/**
 * @brief Scan the given range of ports
 * 
 * @param args struct of arguments
 * svc_list: pointer to the list of service to be updated
 * start_port: start of the port scan range
 * end_port: end of the port scan range
 * hints: connection information
 * @return void* 
 */
void *scan_range(struct scan_args *args) {
	int sockfd;  
	struct addrinfo *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char port[8];

	int start_port = args->start_port;
	int end_port = args->end_port;
	struct service *svc_list = args->svc_list;
	struct addrinfo hints = args->hints;

	int syn_scan = 1;
	const int synRetries = 1;

	int current_port;
	for (current_port = start_port ; current_port <= end_port ; current_port++) {
		if ((rv = getaddrinfo(args->hostname, svc_list[current_port - start_port].port, &hints, &servinfo)) != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		}

		p = servinfo;
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		// SYN SCAN
		if (syn_scan == 1) {
			setsockopt(sockfd, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries));
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
			args->svc_list[current_port - start_port].state = 0;
			close(sockfd);
			continue;
		} else {
			args->svc_list[current_port - start_port].state = 1;
			close(sockfd);
			continue;
		}

		if (p == NULL) {
			fprintf(stderr, "client: failed to connect\n");
		}

		inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
				s, sizeof s);

		freeaddrinfo(servinfo); // all done with this structure

		close(sockfd);
	}
	free(args);
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	int start_port, end_port;
	char port[8];
	struct service *svc_list;
	
	int max_threads = 1; // Maximum number of available threads (can be changed via command argument)
	int nb_threads = 1; // Final number of threads used to run the program
	pthread_t num_thread[nb_threads];

	// Default port range
	start_port = 1;
	end_port = 1024;

	// Arguments parsing
	if (argc > 2) {
		for(int i = 2 ; i < argc - 1 ; i++) {
			if(strcmp(argv[i], "-sp") == 0 || strcmp(argv[i], "--startport") == 0) {
				start_port = atoi(argv[i+1]);
				i++;
			} else if(strcmp(argv[i], "-ep") == 0 || strcmp(argv[i], "--endport") == 0) {
				end_port = atoi(argv[i+1]);
				i++;
			} else if(strcmp(argv[i], "-mth") == 0|| strcmp(argv[i], "--maxthreads") == 0) {
				max_threads = atoi(argv[i+1]);
				i++;
			} else {
				fprintf(stderr, "\033[31;1;4mUSER ERROR:\033[0m Unknown argument: %s\n", argv[i]);
				exit(1);
			}

		}
	} else if (argc < 2 && argc > 8) {
		fprintf(stderr,"\033[31;1;4mUSER ERROR:\033[0m Wrong number of arguments\n\nusage: scanner hostname [port_range_start port_range_end]\n\nNote: the default range is 1-1024\n");
	    exit(1);
	}
	
	// Value error handling
	if (start_port < 1 && end_port > 65535 && end_port < start_port && start_port > end_port) {
		fprintf(stderr, "\033[31;1;4mUSER ERROR:\033[0m port range must be within 1-65535 (cf: RFC 1700)\n");
		exit(1);
	} else if (start_port == end_port) {
		fprintf(stderr, "\033[31;1;4mUSER ERROR:\033[0m end port must be greater than start port (cf: RFC 1700)\n");
		exit(1);
	}

	// Create and fill the list of possibles services (servine name / port)
	svc_list = malloc(((end_port - start_port) + 1) * sizeof(struct service));
	if (get_svc_list(svc_list, start_port, end_port) == 1) {
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int nb_ports = (end_port - start_port) + 1;

	// Finding the optimal number of threads for the current range (below the max threads value)
	int remainder = nb_ports % max_threads;
	while(remainder != 0 && max_threads < nb_ports) {
		nb_ports = max_threads;
		nb_threads = remainder;
		remainder = nb_ports % max_threads;
	}

	int port_slice = (end_port - start_port) / nb_threads;
	int last_end_port = start_port;
	int i = 0;
	
	printf("Scanning in progress...\n\n");
	for(int i = 0 ; i < nb_threads ; i++) {
		struct scan_args *args = malloc(2 * sizeof(int) + sizeof(svc_list) + sizeof(argv[1]) + sizeof(hints));
		args->svc_list = svc_list;
		args->hostname = argv[1];
		args->hints = hints;
		args->start_port = start_port + (i * port_slice);
		args->end_port = last_end_port + port_slice;
		if (args->end_port > end_port) {
			args->end_port = end_port;
		}
		if(pthread_create(&num_thread[i], NULL, scan_range, args) == -1) {
			perror("Cannot create thread\n");
		}
		last_end_port = args->end_port + 1;
		args->start_port++;
	}

	for(int j = 0 ; j < nb_threads ; j++) {
		pthread_join(num_thread[j], NULL);
	}

	display(svc_list, start_port, end_port);
	free(svc_list);
	return 0;
}

