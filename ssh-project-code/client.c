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
#define BLOCKSIZE 16 // aes (our encryption algorithm) cipher size is 16

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
    assert(binaryPacket != NULL);
    binaryPacket -> size = totalSize;
    binaryPacket -> data = malloc(totalSize);
    assert(binaryPacket -> data != NULL);

    /*
        Copy contents into our packet (binaryPacket)
    */
    memcpy(binaryPacket -> data, &packetLength, 4); // length of packet
    memcpy(binaryPacket -> data + 4, &paddingLength, 1); // padding length
    memcpy(binaryPacket -> data + 5, payload -> data, payload -> size); // payload
    memcpy(binaryPacket -> data + 5 + payload -> size, padding -> data, padding -> size); // random padding

    free(padding -> data);
    free(padding);

    return binaryPacket;
}

size_t writeAlgoList(unsigned char *buffer, const char *list) {
    uint32_t len = htonl(strlen(list));
    memcpy(buffer, &len, sizeof(len));       // Write the length prefix
    memcpy(buffer + sizeof(len), list, strlen(list));  // Write the name-list
    return sizeof(len) + strlen(list);
}

// remember to free both struct AND data
RawByteArray *constructKexPayload() {
    size_t offset = 0;
    // for now hard coding buffer size is fine bc we dont have many algos, but in the future
    // we should either be smarter with how we allocate, or use malloc() and realloc()
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer    

    buffer[0] = SSH_MSG_KEXINIT;
    offset += 1;

    RawByteArray *cookie = generateRandomBytes(16);
    memcpy(buffer + offset, cookie -> data, 16);
    offset += 16;
    free(cookie -> data);
    free(cookie);

    // in the future, prob want to import the list of algorithms from config file, not hard 
    // code them in
    const char *kex_algorithms = "diffie-hellman-group14-sha256";
    offset += writeAlgoList(buffer + offset, kex_algorithms);

    const char *server_host_key_algorithms = "ssh-ed25519-cert-v01@openssh.com";
    offset += writeAlgoList(buffer + offset, server_host_key_algorithms);
    
    const char *encryption_algorithms_client_to_server = "aes256-gcm@openssh.com";
    offset += writeAlgoList(buffer + offset, encryption_algorithms_client_to_server);
    
    const char *encryption_algorithms_server_to_client = "aes256-gcm@openssh.com";
    offset += writeAlgoList(buffer + offset, encryption_algorithms_server_to_client);
    
    const char *mac_algorithms_client_to_server = "none";
    offset += writeAlgoList(buffer + offset, mac_algorithms_client_to_server);
    
    const char *mac_algorithms_server_to_client = "none";
    offset += writeAlgoList(buffer + offset, mac_algorithms_server_to_client);
    
    const char *compression_algorithms_client_to_server = "none";
    offset += writeAlgoList(buffer + offset, compression_algorithms_client_to_server);
    
    const char *compression_algorithms_server_to_client = "none";
    offset += writeAlgoList(buffer + offset, compression_algorithms_server_to_client);
    
    const char *languages_client_to_server = "";
    offset += writeAlgoList(buffer + offset, languages_client_to_server);
    
    const char *languages_server_to_client = "";
    offset += writeAlgoList(buffer + offset, languages_server_to_client);

    // Add boolean (first_kex_packet_follows)
    buffer[offset] = 0;
    offset += 1;

    uint32_t reserved = htonl(0);  // Reserved field, set to 0
    buffer[offset] = reserved;
    offset += 4;
    
    RawByteArray *payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);
    payload -> data = malloc(offset);
    assert(payload -> data != NULL);
    // payload -> data = buffer;
    // need to do it this way, or memory leak ensues
    memcpy(payload->data, buffer, offset);
    payload -> size = offset;
    
    return payload;
}

// should add error codes later
int sendProtocol(int sock) {
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

    return 0;
}

// returns pointer to RawByteArray stuct that includes the generated random bytes in data variable
// remember to FREE the struct AND data when done with it
RawByteArray* generateRandomBytes(int numBytes) {
    // seeding random number generator using VERY specific clock time
    struct timespec ts;
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

int sendKexInit (int sock) {
    RawByteArray *payload = constructKexPayload();
    RawByteArray *packet = constructPacket(payload);
    
    // printing for debugging:
    // printf("PACKET:\n");
    // for (int i = 0; i < packet -> size; i++) {
    //     printf("%02x ", packet->data[i]);
    // }
    // printf("\n");
        
    int sentBytes = send(sock, packet -> data, packet -> size, 0);

    free(payload->data);
    free(payload);
    free(packet->data);
    free(packet);
    
    if (sentBytes != -1) {
        printf("Successful kex send! Number of kex bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    unsigned char buffer[BUFFER_SIZE];
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