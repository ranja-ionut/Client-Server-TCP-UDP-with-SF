#include "helpers.h"
#include <math.h>

void usage(char *file, int option) {
    switch (option) {
        case 1:
        fprintf(stderr,
        "Client ID must be between 1 and %i characters long.\n", ID_MAX_LEN);
        exit(0);
        case 2:
        fprintf(stderr, "Server IP must be a valid IPv4 address format.\n");
        exit(0);
        case 3:
        fprintf(stderr, "Server PORT must be a valid PORT.\n");
        exit(0);
        default:
        fprintf(stderr, "Usage: %s ID_CLIENT IP_SERVER PORT_SERVER.\n", file);
        exit(0);    
    }
}

void usage_checker(int argc, char **argv){
    if (argc < 4) {
        usage(argv[0], 0);
    }

    if (strlen(argv[1]) > ID_MAX_LEN) {
        usage(argv[0], 1);
    }

    if (strlen(argv[2]) > 15) {
        usage(argv[0], 2);
    }
    
    char checker[16], *field;
    int fields = 0;

    memcpy(checker, argv[2], sizeof(checker));

    field = strtok(checker, ".");
    
    if (field == NULL) {
        usage(argv[0], 2);
    }

    while (field != NULL) {
        if (strlen(field) == 0 || (atoi(field) == 0 
            && field[0] != '0') || atoi(field) > 255) {
            usage(argv[0], 2);
        }

        field = strtok(NULL, ".");
        fields++;
    }

    if (fields != 4) {
        usage(argv[0], 2);
    }

    if (atoi(argv[3]) == 0) {
        usage(argv[0], 3);
    }
}

void print_payload(char *packet, int p_len){
    struct payload_header *p_header = (struct payload_header *)packet;
    struct payload_data *p_data = (struct payload_data *)(packet +
                                   sizeof(struct payload_header));

    int offset = PAYLOAD_DATA_SIZE + sizeof(struct payload_header);

    printf("%s:%i - ",
    inet_ntoa(p_header->client_addr.sin_addr),
    ntohs(p_header->client_addr.sin_port));

    long int li_number;
    double d_number;
    float sr_number;

    printf("%s - ", p_data->topic);
    switch(p_data->tip_date){
        case 0: 
            printf("INT - ");
            struct INT *i_pl = (struct INT *)(packet + offset);

            li_number = ntohl(i_pl->data);

            printf("%li\n", i_pl->sign == 0 ? li_number : -li_number);
            break;
        case 1: 
            printf("SHORT REAL - ");
            struct SHORT_REAL *sr_pl = (struct SHORT_REAL *)(packet + offset);

            sr_number = (float)ntohs(sr_pl->mod);

            printf("%.2lf\n", sr_number / 100);
            break;
        case 2: 
            printf("FLOAT - ");
            struct FLOAT *f_pl = (struct FLOAT *)(packet + offset);

            d_number = ntohl(f_pl->mod);
            d_number *= pow(10, -f_pl->power);

            printf("%lf\n", f_pl->sign == 0 ? d_number : -d_number);
            break;
        case 3: 
            printf("STRING - ");
            struct STRING *s_pl = (struct STRING *)(packet + offset);

            printf("%s\n", s_pl->message);
            break;
        default:
            break;
    }
}

int main(int argc, char **argv) {
    usage_checker(argc, argv);

    int server_sockfd, ret;

    struct sockaddr_in server_addr;
    
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(server_sockfd < 0, "socket");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[3]));
    ret = inet_aton(argv[2], &server_addr.sin_addr);
    DIE(ret == 0, "inet_aton");

    // Disable Nagle
    int enable = 1;
    if (setsockopt(server_sockfd, IPPROTO_TCP,
                   TCP_NODELAY, &enable, sizeof(int))  == -1) {
        perror("setsocketopt");
        exit(1);            
    }

    ret = connect(server_sockfd, (struct sockaddr *) &server_addr,
                  sizeof(server_addr));
    DIE(ret < 0, "connect");

    char id[ID_MAX_LEN];
    memset(id, 0, sizeof(id));
    memcpy(id, argv[1], strlen(argv[1]));

    int bytes_sent = 0, bytes_remaining = strlen(id);

    do { 
        int rc = send(server_sockfd, &id[bytes_sent], bytes_remaining, 0);
        if(rc < 0) break; // Fix possible error

        bytes_sent += rc;
        bytes_remaining -= rc;
    } while(bytes_remaining > 0);

    fd_set set, temp;
    
    int fd_max = server_sockfd;

    FD_ZERO(&set);
    FD_ZERO(&temp);

    FD_SET(STDIN_FILENO, &set);
    FD_SET(server_sockfd, &set);

    char input[MAX_TOPIC_LEN + CMD_MAX_LEN + 5];

    int max_size = MAX_PKT_SIZE + sizeof(struct sockaddr_in)
                     + sizeof(unsigned int);

    char packet[max_size];

    forever {
        temp = set;

        ret = select(fd_max + 1, &temp, NULL, NULL, NULL);
        DIE(ret < 0, "select");

        if (FD_ISSET(STDIN_FILENO, &temp)) { // se citeste de la tastatura
            memset(input, 0, sizeof(input));
            fgets(input, MAX_TOPIC_LEN + CMD_MAX_LEN + 4, stdin);
            
            if (strncmp(input, "exit", 4) == 0) {
                shutdown(server_sockfd, SHUT_RDWR);
                break;
            }

            struct client_cmd new_cmd;

            char cmd[CMD_MAX_LEN], topic[MAX_TOPIC_LEN + TOPIC_SAFETY_CHECK];
            char SF;

            memset(new_cmd.command, 0, sizeof(new_cmd.command));
            memset(new_cmd.topic, 0, sizeof(new_cmd.topic));

            char *params = strtok(input, " \n");

            if (params != NULL) {
                memcpy(cmd, params, sizeof(cmd));
                params = strtok(NULL, " \n");
            } else {
                printf("bad command\n");
                continue;
            }

            if (params != NULL) {
                memcpy(topic, params, sizeof(topic));
                params = strtok(NULL, " \n");
            } else {
                printf("bad command\n");
                continue;
            }

            if (strncmp(cmd, SUBSCRIBE_CMD, SUBSCRIBE_CMD_SIZE) == 0) {
                memcpy(new_cmd.command, cmd, sizeof(cmd));

                if(strlen(topic) <= MAX_TOPIC_LEN){
                    memcpy(new_cmd.topic, topic, strlen(topic));
                } else {
                    printf("bad command\n");
                    continue;
                }

                if (params != NULL) {
                    memcpy(&SF, params, 1);
                    params = strtok(NULL, " \n");
                } else {
                    printf("bad command\n");
                    continue;
                }

                // check if there is something after the command
                if (params != NULL) {
                    printf("bad command\n");
                    continue;
                }

                if (SF == '0' || SF == '1') {
                    new_cmd.SF = (unsigned char) SF;

                    send(server_sockfd, (char *) &new_cmd, sizeof(new_cmd), 0);
                } else {
                    printf("bad command\n");
                    continue;
                }
            } else {
                // check if there is something after the command
                if (params != NULL) {
                    printf("bad command\n");
                    continue;
                }

                if (strncmp(cmd, UNSUBSCRIBE_CMD, UNSUBSCRIBE_CMD_SIZE) == 0) {
                    memcpy(new_cmd.command, cmd, sizeof(cmd));

                    if(strlen(topic) <= MAX_TOPIC_LEN){
                        memcpy(new_cmd.topic, topic, strlen(topic));
                    } else {
                        printf("bad command\n");
                        continue;
                    }

                    send(server_sockfd, (char *) &new_cmd, sizeof(new_cmd), 0);
                } else {
                    printf("bad command\n");
                    continue;
                }
            }

            char confirm_command[WARNING_SIZE];

            ret = recv(server_sockfd, confirm_command, WARNING_SIZE, 0);

            printf("%s\n", confirm_command);
            fflush(stdout);
        }

        if (FD_ISSET(server_sockfd, &temp)) { // se citeste de la server
            memset(packet, 0, max_size);

            // Ma astept ca packetul primit sa fie ori mesaj de 
            // eroare ori header
            int rc = recv(server_sockfd, packet, WARNING_SIZE, 0);
            if(rc < 0) continue; // Error handling

            if(rc == 0){ // S-a inchis conexiunea
                break;
            } else {
                if (strncmp(packet, WARNING, WARNING_SIZE) == 0) {
                    printf("%s", packet);
                } else {
                    int pkt_size = atoi(packet);

                    if (pkt_size != 0) {
                        int rc = recv(server_sockfd, packet, pkt_size, 0);
                        if(rc < 0) continue; // Error handling

                        print_payload(packet, pkt_size);
                    } else continue; // Error handling
                }
                
                fflush(stdout);
            }
        }

    }

    close(server_sockfd);
    
    return 0;
}