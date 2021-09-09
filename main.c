#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define NEXT_IP SIGUSR1
#define VALID_SCAN SIGUSR2

// mutex to keep lock so no rescans
pthread_mutex_t lock;

// scan params
struct SCAN_DATA {
    int ip1, ip2, ip3, ip4, eip1, eip2, eip3, eip4;
    int port;
    char file_path[255];
};

struct SCAN_DATA *buffer = NULL;

// state
int running = 0;

void usage(char *name) {
    printf("USAGE: %s ip1 ip2 ip3 ip4 eip1 eip2 eip3 eip4 port /path/to/save.txt\n", name);
}

void *parentThread() {
    while (running == 1) {
        sleep(1);
    }
    printf("Scanning finished on %d.%d.%d.%d\n", buffer->ip1, buffer->ip2, buffer->ip3, buffer->ip4);
}

int connectAttempt(char addr[], int port) {
    struct sockaddr_in address;  /* the libc network address data structure */
    short int sock = -1;         /* file descriptor for the network socket */
    fd_set fdset;
    struct timeval tv;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(addr); /* assign the address */
    address.sin_port = htons(port);            /* translate int2port num */

    sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    connect(sock, (struct sockaddr *)&address, sizeof(address));

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 2;             /* 10 second timeout */
    tv.tv_usec = 0;

    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1)
    {
        int so_error;
        socklen_t len = sizeof so_error;

        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            close(sock);
            return 0;
        }
    }

    close(sock);
    return -1;

    return 0;
}

int scanIp(int ip1, int ip2, int ip3, int ip4, int port) {
    char address[17];
    char p[4];
    address[0] = '\0';
    sprintf(p, "%d", ip1);
    strcat(address, p);
    strcat(address, ".");
    sprintf(p, "%d", ip2);
    strcat(address, p);
    strcat(address, ".");
    sprintf(p, "%d", ip3);
    strcat(address, p);
    strcat(address, ".");
    sprintf(p, "%d", ip4);
    strcat(address, p);

    printf("    knocking %s:%d\n", address, port);

    int result = connectAttempt(address, port);

    if (result > -1) {
        printf("    successfully connect to %s:%d\n", address, port);
    }
    return result;
}

void *scannerThread() {
    int ip1, ip2, ip3, ip4, port;
    while (running == 1) {
        int status = pthread_mutex_trylock(&lock);

        // this way scan doesn't cause lock to hold up
        ip1 = buffer->ip1;
        ip2 = buffer->ip2;
        ip3 = buffer->ip3;
        ip4 = buffer->ip4;
        port = buffer->port;

        if (status != EBUSY) {
            buffer->ip4 += 1;
            if (buffer->ip4 > 255) {
                buffer->ip4 = 1;
                buffer->ip3 += 1;
            }
            if (buffer->ip3 > 255) {
                buffer->ip3 = 0;
                buffer->ip2 += 1;
            }
            if (buffer->ip2 > 255) {
                buffer->ip2 = 0;
                buffer->ip1 += 1;
            }

            if (buffer->ip1 > 254) { // how
                running = 0;
            }

            if (buffer->ip4 > buffer->eip4 && buffer->ip3 >= buffer->eip3 && buffer->ip2 >= buffer->eip2 && buffer->ip1 >= buffer->eip1) {
                running = 0;
            }

            status = pthread_mutex_unlock(&lock);
            scanIp(ip1, ip2, ip3, ip4, port);

        }
    }
}

int setup(int count, char *arguments[]) {
    if (count < 11) {
        usage(arguments[0]);
        return 0;
    } else {
        int ip1 = atoi(arguments[1]);
        int ip2 = atoi(arguments[2]);
        int ip3 = atoi(arguments[3]);
        int ip4 = atoi(arguments[4]);

        int eip1 = atoi(arguments[5]);
        int eip2 = atoi(arguments[6]);
        int eip3 = atoi(arguments[7]);
        int eip4 = atoi(arguments[8]);

        int port = atoi(arguments[9]);

        char file_path[255];
        if (strlen(arguments[10]) < 255) {
            strcpy(file_path, arguments[10]);
        } else {
            usage(arguments[0]);
            printf("    file path length is too long must be less than 255 characters\n");
            return 0;
        }

        // sanity check
        if (ip1 <= eip1 && ip2 <= eip2 && ip3 <= eip3 && ip4 < eip4 && port > 0) {
            printf("starting to run scan from %d.%d.%d.%d to %d.%d.%d.%d port %d\n", ip1, ip2, ip3, ip4, eip1, eip2, eip3, eip4, port);
            printf("    saving to: %s\n", file_path);

            buffer = (struct SCAN_DATA*)mmap(0, sizeof(buffer), PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS, -1, 0);
            buffer->ip1 = ip1;
            buffer->ip2 = ip2;
            buffer->ip3 = ip3;
            buffer->ip4 = ip4;
            buffer->eip1 = eip1;
            buffer->eip2 = eip2;
            buffer->eip3 = eip3;
            buffer->eip4 = eip4;
            buffer->port = port;
            strcpy(buffer->file_path, arguments[10]);

            return 1;
        } else {
            usage(arguments[0]);
            printf("    scan is off check numbers \n");
            return 0;
        }
    }
}

void catchInt(int signal) {
    if (signal == SIGTERM || signal == SIGKILL) {
        running = 0;
    }
}

int main(int count, char *arguments[]) {
    // validate it
    int check = setup(count, arguments);

    // something is off
    if (check == 0) {
        return 0;
    }

    // get the handler
    signal(SIGTERM, catchInt);

    running = 1;

    pthread_t parent_thread;
    pthread_t scan_threads[100];

    pthread_mutex_init(&lock, 0);

    if (pthread_create(&parent_thread, NULL, parentThread, NULL)) {
        printf("OOOF creating parent thread failed\n");
        return -1;
    }

    for (int i = 0; i < 100; i += 1) {
        if (pthread_create(&scan_threads[i], NULL, scannerThread, NULL)) {
            printf("OOOF creating scan thread failed [%i]\n", i);
        }
    }

    if (pthread_join(parent_thread, NULL)) {
        printf("OOOF joining parent thread failed\n");
        return -1;
    }

    for (int i = 0; i < 100; i += 1) {
        if (pthread_join(scan_threads[i], NULL)) {
            printf("OOOF joining scan thread failed [%i]\n", i);
        }
    }

    printf("Scan complete or cancelled\n");
    return 0;
}