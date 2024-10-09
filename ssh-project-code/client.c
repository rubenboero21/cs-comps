#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include "client.h"

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20
#define BLOCKSIZE 16

// reconfigure function to return fully formed buffer instead of struct
// remember to free the struct AND data
RawByteArray *constructPacket(RawByteArray *payload) {
    
    /*
        Calculate padding length, calculate packet length, generate random padding, calculate TOTAL packet size
    */
    size_t payloadLength = payload->size;
    
    unsigned char paddingLength = BLOCKSIZE - ((payloadLength + 5) % BLOCKSIZE);

    uint32_t packetLength = htonl(1 + payloadLength + paddingLength);

    RawByteArray *padding = generateRandomBytes(paddingLength);
    
    // size of packet length + size of padding length + size of payload + size of padding 
    size_t totalSize = 4 + 1 + payload -> size + padding -> size;

    RawByteArray *binaryPacket = malloc(sizeof(RawByteArray));
    binaryPacket -> size = totalSize;
    binaryPacket -> data = malloc(totalSize);

    /*
        Copy contents into our packet (binaryPacket)
    */
    memcpy(binaryPacket -> data, &packetLength, 4); // length of packet
    memcpy(binaryPacket -> data + 4, &paddingLength, 1); // padding length
    memcpy(binaryPacket -> data + 5, payload -> data, payload -> size); // payload
    memcpy(binaryPacket -> data + 5 + payload -> size, padding -> data, padding -> size); // random padding

    return binaryPacket;
}

// unsigned char *constructKexPayload() {
    
// }


// should add error codes later
int sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    // send client protocol to server
    // including null terminator just to be safe, strlen wont include it when it sends packet
    char *protocol = "SSH-2.0-mySSH\r\n\0";
    int sentBytes = send(sock, protocol, strlen(protocol), 0);
    // need the null terminator to end the stream, this allows the next packet to be sent
    send(sock, "\0", 1, 0);

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

// returns pointer to RawByteArray stuct that includes the generated random bytes in data variable
// remember to FREE the struct AND data when done with it
RawByteArray* generateRandomBytes(int numBytes) {
    // seeding random number generator using VERY specific clock time
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srandom(ts.tv_sec ^ ts.tv_nsec);

    // allocate space for the struct
    RawByteArray *bytes = malloc(sizeof(RawByteArray));
    assert(bytes != NULL);

    // allocate space for the data
    bytes->data = malloc(numBytes);
    assert(bytes->data != NULL);

    bytes->size = numBytes;

    for (int i = 0; i < numBytes; i++) {
        bytes->data[i] = random() % 256;
    }

    return bytes;
}

// this func is in shambles, we have started to build the kex packet in accordance to binary packet protocol,
// but it is not finished
int sendKexInit (int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    RawByteArray *cookie = generateRandomBytes(16);

    // this is hardcoded, just trying to get it to work
    uint32_t packetLen = 24;
    packetLen = htonl(packetLen); // fix endian-ness
    memcpy(buffer, &packetLen, sizeof(packetLen)); // packet len = 24
    buffer[4] = 6; // padding len = 6

    buffer[5] = SSH_MSG_KEXINIT;
    memcpy(buffer + 6, cookie->data, 16); 
    free(cookie->data);
    free(cookie);
    
    memset(buffer + 22, 0, 2);
    
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

    RawByteArray *cookie = generateRandomBytes(16);

    printf("random cookie:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", cookie->data[i]);
    }
    printf("\n");

    // remember to free both data AND struct itself 🍪
    free(cookie->data);
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