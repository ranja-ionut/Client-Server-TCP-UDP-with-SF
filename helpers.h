#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include "queue.h"
#include "list.h"

// Functiile de conversie
#include <arpa/inet.h> 

// Socketi
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>

// Adrese
#include <netinet/in.h>

/**
 * Macro de verificare a erorilor
 * Exemplu:
 *     int fd = open(file_name, O_RDONLY);
 *     DIE(fd == -1, "open failed");
 */

#define DIE(assertion, call_description)	\
	do {									\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",	\
					__FILE__, __LINE__);	\
			perror(call_description);		\
			exit(EXIT_FAILURE);				\
		}									\
	} while(0)

#define forever while(1)

#define MAX_CLIENTS __INT32_MAX__
#define CMD_MAX_LEN 12
#define ID_MAX_LEN 10
#define MAX_TOPIC_LEN 50
#define TOPIC_SAFETY_CHECK 25
#define MAX_MESSAGE_LEN 1500
#define INIT_CAP 5
#define SUBSCRIBE_CMD "subscribe"
#define SUBSCRIBE_CMD_SIZE (sizeof(SUBSCRIBE_CMD))
#define UNSUBSCRIBE_CMD "unsubscribe"
#define UNSUBSCRIBE_CMD_SIZE (sizeof(UNSUBSCRIBE_CMD))
#define WARNING "Client ID is already in use!\n"
#define WARNING_SIZE (sizeof(WARNING))

int size = 0, max_cap = INIT_CAP;
struct client *clients;

struct INT {
	uint8_t sign;
	uint32_t data;
}__attribute__((packed));

struct SHORT_REAL {
	uint16_t mod;
}__attribute__((packed));

struct FLOAT {
	uint8_t sign;
	uint32_t mod;
	uint8_t power;
}__attribute__((packed));

struct STRING {
	char message[MAX_MESSAGE_LEN];
}__attribute__((packed));

struct payload_data {
	char topic[MAX_TOPIC_LEN];
	unsigned int tip_date : 8;
}__attribute__((packed));

#define PAYLOAD_DATA_SIZE (MAX_TOPIC_LEN + sizeof(uint8_t))

struct payload_header {
	struct sockaddr_in client_addr;
	unsigned int payload_length;
}__attribute__((packed));

#define SAFETY 5
#define MAX_PKT_SIZE (1551 + SAFETY)

struct client_cmd {
	char command[CMD_MAX_LEN];
	char topic[MAX_TOPIC_LEN];
	unsigned char SF;
}__attribute__((packed));

#define CMD_SIZE (CMD_MAX_LEN + MAX_TOPIC_LEN + 1)
#define CMD_NEW -1
#define CMD_SAME 0
#define CMD_CHANGE_SF 1

struct client {
	struct sockaddr_in client_addr;
	int client_sockfd;
	char id[ID_MAX_LEN];
	list commands;
	queue saved_data;
}__attribute__((packed));

#endif