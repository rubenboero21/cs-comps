#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <errno.h>
#include <stdint.h>

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20

#define MAX_PAYLOAD_SIZE 32768  // Example size limit (adjust as necessary)
#define MAX_PADDING_SIZE 255    // Maximum padding length (1 byte field)
#define MAX_MAC_SIZE 64         // Maximum MAC size for various algorithms (HMAC, etc.)

// Struct to represent an SSH binary packet
typedef struct {
    uint32_t packet_length;          // Length of the packet (excluding the MAC)
    uint8_t padding_length;          // Number of padding bytes
    unsigned char payload[MAX_PAYLOAD_SIZE];  // Payload data
    unsigned char padding[MAX_PADDING_SIZE];  // Padding data
} SSHBinaryPacket;



// should add error codes later
void sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    // send client protocol to server
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
}

// generates random 16 byte cookie for key exchange
void generateRandomCookie(unsigned char *cookie) {
    srandom((unsigned int)time(NULL));

    // generate a random 1 byte number 16 times
    for (int i = 0; i < 16; i++) {
        cookie[i] = random() % 256;
    }
}

// this func is in shambles, we have started to build the kex packet in accordance to binary packet protocol,
// but it is not finished
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
    
    int sentBytes = send(sock, buffer, 24, 0);
    if (sentBytes != -1) {
        printf("Successful kex send! Number of kex bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    ssize_t bytes_recieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_recieved > 0) {
        printf("response: %s\n", buffer);
    } else {
        printf("No server response recieved :(\n");
    }
}

void start_client(const char *host, const int port) {
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