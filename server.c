#include "helpers.h"

void usage(char *file, int option) {
    switch(option){
        case 1:
            fprintf(stderr, "Server PORT must be a valid PORT.\n");
            exit(0);
        default:
            fprintf(stderr, "Usage: %s PORT_SERVER.\n", file);
            exit(0);    
    }
}

int get_client_index(char *id, int sockfd) {
    int i = 0;

    if(sockfd == -1){
        for (i = 0; i < size; i++){
            if (strcmp(id, clients[i].id) == 0) {
                return i;
            }
        }
    }

    if(id == NULL){
        for (i = 0; i < size; i++){
            if (sockfd == clients[i].client_sockfd) {
                return i;
            }
        }
    }

    return -1;
}

void delete_client(int index) {
    if (clients[index].commands != NULL) {
        list aux = clients[index].commands;
        while(aux != NULL) {
            list free_aux = aux;
            aux = aux->next;

            if (free_aux != NULL) {
                if (free_aux->element != NULL) {
                    free(free_aux->element);
                }

                free(free_aux);
            }
        }
    }

    while (!queue_empty(clients[index].saved_data)) {
        char *data = queue_deq(clients[index].saved_data);
        free(data);
    }

    if (clients[index].saved_data != NULL)
        free(clients[index].saved_data);
}

int has_command(list commands, struct client_cmd *cmd) {
    list aux = commands;

    while (aux != NULL) {
        struct client_cmd *aux_cmd = (struct client_cmd *)aux->element;

        // Acelasi topic
        if (strcmp(aux_cmd->topic, cmd->topic) == 0) {
            // Acelasi SF
            if (aux_cmd->SF == cmd->SF) {
                return CMD_SAME; // Comanda exista deja
            } else return CMD_CHANGE_SF; // S-a modificat campul SF
        }

        // Daca nu au acelasi topic continua parcurgerea
        aux = aux->next;
    }

    // Comanda data este una noua
    return CMD_NEW;
}

void handle_command(struct client_cmd *cmd, int client) {
    list aux, prev;
    struct client_cmd *prev_cmd, *aux_cmd;

    if (strcmp(cmd->command, SUBSCRIBE_CMD) == 0) {
        int ret = has_command(clients[client].commands, cmd);

        switch (ret) {
            case CMD_NEW:
                aux = malloc(sizeof(struct cell));

                aux->element = malloc(sizeof(struct client_cmd));
                memcpy(aux->element, cmd, sizeof(struct client_cmd));

                aux->next = clients[client].commands;
                clients[client].commands = aux;
            break;

            case CMD_SAME: // Daca exista 2 comenzi de subscribe se ignora
            break;

            case CMD_CHANGE_SF:
                aux = clients[client].commands;

                while (aux != NULL) {
                    aux_cmd = (struct client_cmd *)aux->element;

                    if (strcmp(aux_cmd->topic, cmd->topic) == 0) {
                        aux_cmd->SF = cmd->SF;
                    }
                    
                    aux = aux->next;
                }
            break;
            default:
            break;
        }

        char confirm_command[WARNING_SIZE];
        memset(confirm_command, 0, WARNING_SIZE);
        memcpy(confirm_command, "subscribed topic\n",
               sizeof("subscribed topic\n"));

        int bytes_sent = 0, bytes_remaining = sizeof(confirm_command);

        if  (clients[client].client_sockfd != -1) {
            do { 
                int rc = send(clients[client].client_sockfd, 
                            &confirm_command[bytes_sent], bytes_remaining, 0);
                if(rc < 0) break; // Fix possible error

                bytes_sent += rc;
                bytes_remaining -= rc;
            } while(bytes_remaining > 0);
        }
    }

    if (strcmp(cmd->command, UNSUBSCRIBE_CMD) == 0) {
        prev = clients[client].commands;

        // Handle suspicious possible problem
        if (prev == NULL) {
            char confirm_command[WARNING_SIZE];
            memset(confirm_command, 0, WARNING_SIZE);
            memcpy(confirm_command, "not subscribed to it\n",
                    sizeof("not subscribed to it\n"));

            int bytes_sent = 0, bytes_remaining = sizeof(confirm_command);

            if  (clients[client].client_sockfd != -1) {
                do { 
                    int rc = send(clients[client].client_sockfd, 
                                &confirm_command[bytes_sent], bytes_remaining, 0);
                    if(rc < 0) break; // Fix possible error

                    bytes_sent += rc;
                    bytes_remaining -= rc;
                } while(bytes_remaining > 0);
            }

            return;
        }
        
        prev_cmd = (struct client_cmd *)prev->element;

        if(strcmp(prev_cmd->topic, cmd->topic) == 0){
            clients[client].commands = cdr_and_free(prev);

            free(prev_cmd);

            char confirm_command[WARNING_SIZE];
            memset(confirm_command, 0, WARNING_SIZE);
            memcpy(confirm_command, "unsubscribed topic\n",
                    sizeof("unsubscribed topic\n"));

            int bytes_sent = 0, bytes_remaining = sizeof(confirm_command);

            if  (clients[client].client_sockfd != -1) {
                do { 
                    int rc = send(clients[client].client_sockfd, 
                                &confirm_command[bytes_sent], bytes_remaining, 0);
                    if(rc < 0) break; // Fix possible error

                    bytes_sent += rc;
                    bytes_remaining -= rc;
                } while(bytes_remaining > 0);
            }
        } else {
            aux = prev->next;

            while(aux != NULL){
                aux_cmd = (struct client_cmd *)aux->element;

                if (strcmp(aux_cmd->topic, cmd->topic) == 0) {
                    list free_aux = aux;

                    prev->next = aux->next;

                    // Handle suspicious possible problem
                    if (free_aux != NULL) {
                        if (free_aux->element != NULL) {
                            free(free_aux->element);
                        }

                        free(free_aux);
                    }

                    // Handle saved_data

                    // Handle suspicious possible problem
                    if (clients[client].saved_data != NULL) {
                        while (!queue_empty(clients[client].saved_data)) {
                            list free_data = 
                                        queue_deq(clients[client].saved_data);

                            // Handle suspicious possible problem
                            if (free_data != NULL)
                                free(free_data);
                        }
                    }
                    
                    // Handle suspicious possible problem
                    if (clients[client].saved_data != NULL) {
                        free(clients[client].saved_data);
                    }

                    // Recreate saved_data queue for this client
                    clients[client].saved_data = queue_create();

                    char confirm_command[WARNING_SIZE];
                    memset(confirm_command, 0, WARNING_SIZE);
                    memcpy(confirm_command, "unsubscribed topic\n",
                            sizeof("unsubscribed topic\n"));

                    int bytes_sent = 0, bytes_remaining = sizeof(confirm_command);

                    if  (clients[client].client_sockfd != -1) {
                        do { 
                            int rc = send(clients[client].client_sockfd, 
                                        &confirm_command[bytes_sent], bytes_remaining, 0);
                            if(rc < 0) break; // Fix possible error

                            bytes_sent += rc;
                            bytes_remaining -= rc;
                        } while(bytes_remaining > 0);
                    }

                    break;
                }
                        
                prev = aux;
                aux = aux->next;
            }
        }

        char confirm_command[WARNING_SIZE];
        memset(confirm_command, 0, WARNING_SIZE);
        memcpy(confirm_command, "not subscribed to it\n",
                sizeof("not subscribed to it\n"));

        int bytes_sent = 0, bytes_remaining = sizeof(confirm_command);

        if  (clients[client].client_sockfd != -1) {
            do { 
                int rc = send(clients[client].client_sockfd, 
                            &confirm_command[bytes_sent], bytes_remaining, 0);
                if(rc < 0) break; // Fix possible error

                bytes_sent += rc;
                bytes_remaining -= rc;
            } while(bytes_remaining > 0);
        }

        return;

        /*
        Daca s-a ajuns la final atunci automat nu a existat inainte
        o comanda subscribe care sa poate fi stearsa.
        */
    }
}

int has_topic(list commands, char *topic) {
    list aux = commands;

    while (aux != NULL) {
        struct client_cmd *aux_cmd = (struct client_cmd *)aux->element;

        if (strcmp(aux_cmd->topic, topic) == 0) {
            if (aux_cmd->SF == '1') {
                return 2;
            }

            return 1;
        }

        aux = aux->next;
    }

    return 0;
}

void send_payload(int sockfd, char *payload) {
    if (sockfd == -1) return;

    int index = get_client_index(NULL, sockfd);

    int bytes_remaining = 0, bytes_sent = 0;

    struct payload_header *p_header = (struct payload_header *)payload;

    bytes_remaining += p_header->payload_length;

    int sc;

    /*
        WARNING_SIZE fiind mai cuprinzator si clientul putand primi si un 
        WARNING am decis ca mesajul meta_data va fi tot de WARNING_SIZE.
    */
    char meta_data[WARNING_SIZE];
    memset(meta_data, 0, WARNING_SIZE);
    sprintf(meta_data, "%i", bytes_remaining);

    // Send meta_data
    sc = send(sockfd, meta_data, WARNING_SIZE, 0);
    if (sc < 0) {
        clients[index].client_sockfd = -1;

        return;
    }

    // Send the payload
    do {
        sc = send(sockfd, &payload[bytes_sent], bytes_remaining, 0);

        if (sc < 0) {
            clients[index].client_sockfd = -1;
            return;
        }

        bytes_sent += sc;

        bytes_remaining -= sc;
    } while(bytes_remaining > 0);
}

void handle_udp_payloads(char *payload, struct sockaddr_in client, int p_len) {
    struct payload_header p_header;
    p_header.client_addr = client;
    p_header.payload_length = p_len * 1UL + sizeof(struct payload_header);

    struct payload_data *pdata = (struct payload_data *)payload;

    for (int i = 0; i < size; i++) {
        list commands = clients[i].commands;

        int ret = has_topic(commands, pdata->topic);

        if (ret) {
            char *full_payload = calloc(p_header.payload_length, sizeof(char));
            memcpy(full_payload, (char *)&p_header, sizeof(p_header));
            memcpy(&full_payload[sizeof(p_header)], payload, p_len);

            if (clients[i].client_sockfd == -1) {
                if (ret == 2) { // Daca clientul era abonat la topic
                    queue_enq(clients[i].saved_data, full_payload);
                } else {
                    free(full_payload);
                }
            } else { // Send messages now
                send_payload(clients[i].client_sockfd, full_payload);
                free(full_payload);
            }
        }
    }

}

int main(int argc, char **argv) {

    if (argc < 2) {
        usage(argv[0], 0);
    }

    if (atoi(argv[1]) == 0) {
        usage(argv[0], 1);
    }

    // Disable server death from unknown behaviour of client during send
    signal(SIGPIPE, SIG_IGN);

    int i;

    int server_sockfd, new_subscriber_sockfd, udp_sockfd;
    int server_port;

    struct sockaddr_in server_addr, subscriber_addr, udp_client_addr;

    socklen_t subscriber_len;

    fd_set read_fs;
    fd_set tmp_fds;

    int fd_max, ret;

    FD_ZERO(&read_fs);
    FD_ZERO(&tmp_fds);

    // TCP SOCKET

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(server_sockfd < 0, "socket");

    server_port = atoi(argv[1]);
    DIE(server_port == 0, "atoi");

    memset((char *) &server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    int enable = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET,
                   SO_REUSEADDR, &enable, sizeof(int))  == -1) {
        perror("setsocketopt");
        exit(1);            
    }

    // Disable Nagle
    enable = 1;
    if (setsockopt(server_sockfd, IPPROTO_TCP,
                   TCP_NODELAY, &enable, sizeof(int))  == -1) {
        perror("setsocketopt");
        exit(1);            
    }

    ret = bind(server_sockfd, (struct sockaddr *) &server_addr,
               sizeof(struct sockaddr));
    DIE(ret < 0, "bind");

    ret = listen(server_sockfd, MAX_CLIENTS);
    DIE(ret < 0, "listen");

    // UDP SOCKET

    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(server_sockfd < 0, "socket");

    ret = bind(udp_sockfd, (struct sockaddr *) &server_addr,
               sizeof(struct sockaddr));
    DIE(ret < 0, "bind");

    // ADD UPD, TCP SOCKETS + STDIN TO READ_SET
    FD_SET(STDIN_FILENO, &read_fs);
    FD_SET(udp_sockfd, &read_fs);
    FD_SET(server_sockfd, &read_fs);

    fd_max = server_sockfd > udp_sockfd ? server_sockfd : udp_sockfd;

    char input[100], id[ID_MAX_LEN], packet[MAX_PKT_SIZE], command[CMD_SIZE];

    clients = malloc(INIT_CAP * sizeof(struct client));

    forever {
        tmp_fds = read_fs;

        ret = select(fd_max + 1, &tmp_fds, NULL, NULL, NULL);
        DIE(ret < 0, "select");

        // Oprirea serverului ia prioritate
        fflush(stdout);

        if(FD_ISSET(STDIN_FILENO, &tmp_fds)){
            memset(input, 0, sizeof(input));
            fgets(input, 99, stdin);
            
            if (strncmp(input, "exit", 4) == 0) {
                for (i = 0; i < size; i++) {
                    delete_client(i);
                }

                free(clients);

                for (i = 0; i <= fd_max; i++) {
                    if (i != server_sockfd && i != STDIN_FILENO 
                        && i != udp_sockfd) {
                        shutdown(i, SHUT_RDWR);
                        close(i);
                    }
                }

                break;
            }
        }

        if (FD_ISSET(udp_sockfd, &tmp_fds)) {
            memset(packet, 0, MAX_PKT_SIZE);
            memset((char *) &udp_client_addr, 0, sizeof(udp_client_addr));
            socklen_t udp_client_len = sizeof(udp_client_addr);

            ret = recvfrom(udp_sockfd, packet, MAX_PKT_SIZE, 0,
                        (struct sockaddr *) &udp_client_addr, &udp_client_len);
            
            if(ret < 0) continue; // Error handling

            handle_udp_payloads(packet, udp_client_addr, ret);
            fflush(stdout);
        } else {

            for (i = 0; i <= fd_max; i++) {
                if (FD_ISSET(i, &tmp_fds)) {
                    if (i == server_sockfd) { 
                        // am primit cerere de conexiune pe listen
                        subscriber_len = sizeof(subscriber_addr);

                        new_subscriber_sockfd = accept(server_sockfd,
                        (struct sockaddr *) &subscriber_addr, &subscriber_len);
                        DIE(new_subscriber_sockfd < 0, "accept");

                        memset(id, 0, sizeof(id));
                        recv(new_subscriber_sockfd, id, sizeof(id), 0);

                        int index = get_client_index(id, -1);
                        
                        if (index == -1 ||
                             clients[index].client_sockfd == -1) {
                            // adauga noul subscriber la read_fs
                            FD_SET(new_subscriber_sockfd, &read_fs);
                            if(new_subscriber_sockfd > fd_max){
                                fd_max = new_subscriber_sockfd;
                            }

                            printf("New client (%s) connected from %s:%i.\n",
                                id,
                                inet_ntoa(subscriber_addr.sin_addr),
                                subscriber_addr.sin_port);
                        }

                        if (index == -1) { // Client nou
                            if (size == max_cap) {
                                max_cap += size;
                                clients = realloc(clients, 
                                            max_cap * sizeof(struct client));
                            }
                            struct client new_client;
                            memset(new_client.id, 0, ID_MAX_LEN);
                            memcpy(new_client.id, id, strlen(id));

                            char *addr = inet_ntoa(subscriber_addr.sin_addr);
                                
                            inet_aton(addr, &new_client.client_addr.sin_addr);

                            new_client.client_sockfd = new_subscriber_sockfd;

                            new_client.commands = NULL;
                            new_client.saved_data = queue_create();

                            clients[size++] = new_client;
                        } else if (clients[index].client_sockfd == -1) {
                            // Client reconectat
                            clients[index].client_sockfd = 
                                                    new_subscriber_sockfd;

                            // Trimite-i toate mesajele la care a fost abonat
                            while (!queue_empty(clients[index].saved_data)) {
                                char *payload = 
                                        queue_deq(clients[index].saved_data);

                                send_payload(new_subscriber_sockfd, payload);
                                free(payload);
                            }

                        } else { // Caz interzis
                            char *warn = WARNING;
                            
                            int bytes_sent = 0, bytes_remaining = WARNING_SIZE;

                            do { 
                                int rc = send(new_subscriber_sockfd, 
                                        &warn[bytes_sent], bytes_remaining, 0);
                                bytes_sent += rc;
                                bytes_remaining -= rc;
                            } while(bytes_remaining > 0);

                            shutdown(new_subscriber_sockfd, SHUT_RDWR);
                            close(new_subscriber_sockfd);
                            continue;
                        }
                    } else if (i != STDIN_FILENO) {
                        char packet[MAX_PKT_SIZE];
                        
                        memset(packet, 0, MAX_PKT_SIZE);

                        int bytes_received = 0;

                        memset(command, 0, sizeof(command));

                        bytes_received = recv(i, command, sizeof(command), 0);
                        if(bytes_received < 0) continue;

                        int index = get_client_index(NULL, i);

                        if (bytes_received == 0) { // S-a inchis conexiunea 

                            printf("Client (%s) disconnected.\n",
                                     clients[index].id);
                            close(i);

                            clients[index].client_sockfd = -1;

                            FD_CLR(i, &read_fs);
                        } else { // Am primit o posibila comanda
                            struct client_cmd *cmd = 
                                    (struct client_cmd *)command;

                            handle_command(cmd, index);

                            fflush(stdout);
                        }
                    }
                }
            }

        }
    }

    close(server_sockfd);

    return 0;
}