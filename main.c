#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
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

void scanIp(int ip1, int ip2, int ip3, int ip4, int port) {
    printf("    knocking %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
}

void *scannerThread() {
    while (running == 1) {
        int status = pthread_mutex_trylock(&lock);

        if (status != EBUSY) {
            scanIp(buffer->ip1, buffer->ip2, buffer->ip3, buffer->ip4, buffer->port);
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
    pthread_t scan_thread_1, scan_thread_2, scan_thread_3, scan_thread_4;

    pthread_mutex_init(&lock, 0);

    if (pthread_create(&parent_thread, NULL, parentThread, NULL)) {
        printf("OOOF creating parent thread failed\n");
    }

    if (pthread_create(&scan_thread_1, NULL, scannerThread, NULL)) {
        printf("OOOF creating scanner1 thread failed\n");
    }

    if (pthread_create(&scan_thread_2, NULL, scannerThread, NULL)) {
        printf("OOOF creating scanner2 thread failed\n");
    }

    if (pthread_create(&scan_thread_3, NULL, scannerThread, NULL)) {
        printf("OOOF creating scanner3 thread failed\n");
    }

    if (pthread_create(&scan_thread_4, NULL, scannerThread, NULL)) {
        printf("OOOF creating scanner4 thread failed\n");
    }

    if (pthread_join(parent_thread, NULL)) {
        printf("OOOF joining parent thread failed\n");
        return -1;
    }

    if (pthread_join(scan_thread_1, NULL)) {
        printf("OOOF joining scanner1 thread failed\n");
        return -1;
    }

    if (pthread_join(scan_thread_2, NULL)) {
        printf("OOOF joining scanner1 thread failed\n");
        return -1;
    }

    if (pthread_join(scan_thread_3, NULL)) {
        printf("OOOF joining scanner1 thread failed\n");
        return -1;
    }

    if (pthread_join(scan_thread_4, NULL)) {
        printf("OOOF joining scanner1 thread failed\n");
        return -1;
    }

    printf("Scan complete or cancelled\n");
    return 0;
}