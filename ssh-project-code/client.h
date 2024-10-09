
// // Struct to represent an SSH binary packet
// typedef struct {
//     uint32_t packetLength;          // Length of the packet (excluding the MAC)
//     uint8_t paddingLength;          // Number of padding bytes
//     unsigned char *payload;  // pointer to payload data
//     unsigned char *padding;  // Padding data
// } BinaryPacket;

typedef struct {
    unsigned char *data;
    size_t size;
} RawByteArray;

// Return a packet in Binary Packet Protocol with the given payload
/*
Input: Pointer to the payload of a binary packet protocol packet
Output: A buffer containing the raw bytes of the packet.
*/
// BinaryPacket constructPacket(unsigned char *payload);

/*
Input: None (potentially a list of algorithms in the future)
Output: The payload in string form (the list of comma separated algorithms with len in front)
*/
unsigned char *constructKexPayload();

/*
Input: The socket to send the protocol packet to
Output:
*/
int sendProtocol(int sock);

/*
Input: The number of random bytes to generate
Output: A pointer to a RawByteArray struct that contains the random bytes in the data variable
        and the size of the data in size variable
*/
RawByteArray* generateRandomBytes(int numBytes);

/*
*/
int sendKexInit (int sock);

/*
Input: A host and port number to connect to 
Output: SOME ERROR CODES - NEED TO UPDATE
*/
int start_client(const char *host, const int port);
