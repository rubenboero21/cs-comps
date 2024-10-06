#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <errno.h>

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20

// should add error codes later
void sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    // send client protocol to server
    char *protocol = "SSH-2.0-mySSH\r\n";
    send(sock, protocol, strlen(protocol), 0);

    // recieve server response - NOT SURE WHAT TO ACTUALLY DO WITH IT
    ssize_t bytes_recieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_recieved > 0) {
        printf("server protocol: %s", buffer);
    } else {
        printf("No server protocol recieved :(\n");
    }
}

// generates random 16 byte cookie for key exchange
void generateRandomCookie(unsigned char *cookie) {
    srandom((unsigned int)time(NULL));

    // generate a random 1 byte number 16 times
    for (int i = 0; i < 16; i++) {
        cookie[i] = random() % 256;
    }
}

// DOES NOT WORK - WE ARE NOT FOLLOWING BINARY PACKET PROTOCOL - were hoping that send() would handle it for us
void sendKexInit (int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    unsigned char cookie[16];
    generateRandomCookie(cookie);

    // this is hardcoded, just trying to get it to work
    uint32_t packetLen = 24;
    packetLen = htonl(packetLen); // fix endian-ness
    memcpy(buffer, &packetLen, sizeof(packetLen)); // packet len = 24
    buffer[4] = 6; // padding len = 6

    buffer[5] = SSH_MSG_KEXINIT;
    memcpy(buffer + 6, cookie, 16); //
    memset(buffer + 22, 0, 2);

    // printing out packet for debugging
    for (int i = 0; i < 24; i++) {
        printf("%x ",  buffer[i]);
    }
    printf("\n");
    
    send(sock, buffer, 24, 0);
    
    ssize_t bytes_recieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_recieved > 0) {
        printf("response: %s\n", buffer);
    } else {
        printf("No server response recieved :(\n");
    }
}

void start_client() {
    struct sockaddr_in address;
    int sock = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_port = htons(22); // THIS IS THE PORT THAT THE CLIENT CONNECTS TO
    // inet_pton(AF_INET, "127.0.0.1", &address.sin_addr); // this is the host address to connect to
    inet_pton(AF_INET, "192.168.64.6", &address.sin_addr);

    int output = connect(sock, (struct sockaddr *)&address, sizeof(address));
    
    if (output == 0) {
        printf("successful connection\n");
    } else {
        printf("no connection\n");
    }

    sendProtocol(sock);

    // maybe use malloc to make it more clear what is going on - allocating 16 bytes
    unsigned char cookie[16];
    generateRandomCookie(cookie);

    printf("random cookie:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", cookie[i]);
    }
    printf("\n");

    sendKexInit(sock);

    close(sock);
}

int main() {
    start_client();
    return 0;
}