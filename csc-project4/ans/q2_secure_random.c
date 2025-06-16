#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "140.113.207.245"
#define SERVER_PORT 30171
#define BUFFER_SIZE 4096

unsigned int long_secure_random(unsigned int seed) {
    srand(seed);
    unsigned int r[100];
    for (int i = 0; i < 100; i++) {
        r[i] = rand() % 32323;
    }
    for (int i = 1; i < 100; i++) {
        unsigned int a = r[i];
        unsigned int b = r[i - 1];
        r[i] = a * b * b * b + a * b * b * 3 + a * b * 2 + a;
    }
    return r[99];
}

int connect_to_server() {
    int sockfd;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    return sockfd;
}

void recv_until_prompt(int sockfd) {
    char buffer[BUFFER_SIZE];
    int n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        // printf("[Server] %s", buffer);
    }
}

void send_guess(int sockfd, unsigned int guess) {
    char msg[64];
    snprintf(msg, sizeof(msg), "%u\n", guess);
    write(sockfd, msg, strlen(msg));
    // printf("[+] Sent guess: %u\n", guess);
}

void read_response(int sockfd) {
    char buffer[BUFFER_SIZE];
    int n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        if (strstr(buffer, "You succeed") != NULL || strstr(buffer, "CSC2025{") != NULL) {
            printf("%s\n", buffer);
        }
    }
}


int main() {
    for (int offset = -2; offset <= 2; offset++) {
        int sockfd = connect_to_server();
        recv_until_prompt(sockfd);

        time_t base = time(NULL);
        unsigned int seed = (unsigned int)(base + offset);
        unsigned int guess = long_secure_random(seed);

        // printf("\n[*] Trying with seed %u (offset %+d)\n", seed, offset);
        send_guess(sockfd, guess);
        read_response(sockfd);
        close(sockfd);

        sleep(1);
    }

    return 0;
}
