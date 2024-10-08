#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include "client.h"

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20

// reconfigure function to return fully formed buffer instead of struct
BinaryPacket* constructPacket(unsigned char *payload, unsigned int payloadLength) {

    // Calculate padding length to align with the block size (16 bytes for AES)
    unsigned int blockSize = 16;  // Example block size for AES
    unsigned char paddingLength = blockSize - ((payloadLength + 5) % blockSize);  // 5 = packet_length (4) + padding_length (1)

    BinaryPacket *bp = malloc(sizeof(BinaryPacket));

    bp -> packetLength = htonl(paddingLength + payloadLength + 1); // 
    bp -> paddingLength = paddingLength
    bp -> payload = payload;
    bp -> padding = generateRandomBytes(paddingLength);
    
    return bp;
}

// should add error codes later
int sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    // send client protocol to server
    // should we have a null terminator on the end of the string?
    char *protocol = "SSH-2.0-mySSH\r\n";
    int sentBytes = send(sock, protocol, strlen(protocol), 0);

    if (sentBytes != -1) {
        printf("Successful protocol send! Number of protocol bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    ssize_t bytesRecieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytesRecieved > 0) {
        printf("server protocol: %s", buffer);
    } else {
        printf("No server protocol recieved :(\n");
    }

    return 0;
}

// returns pointer to random n byte sequence 
// remember to FREE the bytes when done with it
unsigned char* generateRandomBytes(int numBytes) {
    
    unsigned char *bytes = malloc(16 * sizeof(char));
    srandom((unsigned int)time(NULL));

    // generate a random 1 byte number 16 times
    for (int i = 0; i < 16; i++) {
        bytes[i] = random() % 256;
    }

    return bytes;
}

// this func is in shambles, we have started to build the kex packet in accordance to binary packet protocol,
// but it is not finished
int sendKexInit (int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    unsigned char *cookie = generateRandomBytes(16);

    // // this is hardcoded, just trying to get it to work
    uint32_t packetLen = 24;
    packetLen = htonl(packetLen); // fix endian-ness
    memcpy(buffer, &packetLen, sizeof(packetLen)); // packet len = 24
    buffer[4] = 6; // padding len = 6

    buffer[5] = SSH_MSG_KEXINIT;
    memcpy(buffer + 6, cookie, 16); //
    free(cookie);
    memset(buffer + 22, 0, 2);

    // printing out packet for debugging
    for (int i = 0; i < 24; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
    
    int sentBytes = send(sock, buffer, 24, 0);
    if (sentBytes != -1) {
        printf("Successful kex send! Number of kex bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer
    // recv only returns the ssh payload it seems
    ssize_t bytes_recieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_recieved > 0) {
        printf("response: %s\n", buffer);
    } else {
        printf("No server response recieved :(\n");
    }

    // printing out some of the response (buffer is too small for all of it)
    // for (int i = 0; i < sizeof(buffer); i++) {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

    return 0;
}

int start_client(const char *host, const int port) {
    struct sockaddr_in address;
    int sock = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_port = htons(22); // THIS IS THE PORT THAT THE CLIENT CONNECTS TO
    // inet_pton(AF_INET, "127.0.0.1", &address.sin_addr); // this is the host address to connect to
    inet_pton(AF_INET, host, &address.sin_addr);

    int output = connect(sock, (struct sockaddr *)&address, sizeof(address));
    
    if (output == 0) {
        printf("successful connection\n");
    } else {
        printf("no connection\n");
    }

    sendProtocol(sock);

    unsigned char *cookie = generateRandomBytes(16);

    printf("random cookie:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", cookie[i]);
    }
    printf("\n");
    free(cookie);

    sendKexInit(sock);

    close(sock);

    return 0;
}

int main(int argc, char **argv) {
    // check & get command line arguments
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    const char *host = argv[1];
    const int port = atoi(argv[2]);

    start_client(host, port);
    return 0;
}