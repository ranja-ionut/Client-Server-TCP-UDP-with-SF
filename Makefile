CFLAGS = -Wall -g 
CC = gcc

PORT_SERVER = 8080

IP_SERVER = 127.0.0.1

ID_CLIENT = f_mega

all: server subscriber

server: server.c queue.c list.c

subscriber: subscriber.c queue.c list.c
	${CC} ${CFLAGS} subscriber.c queue.c list.c -o subscriber -lm

.PHONY: clean run_server run_subscriber

run_server:
	./server ${PORT_SERVER}

run_subscriber:
	./subscriber ${ID_CLIENT} ${IP_SERVER} ${PORT_SERVER}

run_udp:
	python3 udp_client.py 127.0.0.1 8080

run_udp_manual:
	python3 udp_client.py --mode manual 127.0.0.1 8080

run_udp_random:
	python3 udp_client.py --source-port 1234 --input_file three_topics_payloads.json --mode random --delay 100 127.0.0.1 8080

clean:
	rm -f server subscriber
