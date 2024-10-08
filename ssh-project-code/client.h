#define MAX_PAYLOAD_SIZE 32768  // Example size limit (adjust as necessary)
#define MAX_PADDING_SIZE 255    // Maximum padding length (1 byte field)
#define MAX_MAC_SIZE 64         // Maximum MAC size for various algorithms (HMAC, etc.)

// Struct to represent an SSH binary packet
typedef struct {
    uint32_t packet_length;          // Length of the packet (excluding the MAC)
    uint8_t padding_length;          // Number of padding bytes
    unsigned char payload[MAX_PAYLOAD_SIZE];  // pointer to payload data
    unsigned char padding[MAX_PADDING_SIZE];  // Padding data
} SSHBinaryPacket;

// Prints the payload of a packet
void printPayload();

/* 
Input: Pointer to SSHBinaryPacket struct
Output: Prints the contents of the SSHBinaryPacket struct (to help with debugging).
*/
void printPacket(SSHBinaryPacket *packet);

// Return a packet in Binary Packet Protocol with the given payload
/*
Input: Pointer to the payload of a binary packet protocol packet
Output: An SSHBinaryPacket struct.
*/
SSHBinaryPacket constructPacket(unsigned char *payload);
