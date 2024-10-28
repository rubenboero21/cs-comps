// a struct to hold data and its size
typedef struct {
    unsigned char *data;
    size_t size;
} RawByteArray;

// a struct to hold the data that the server sends back in step 2 of DH exchange
typedef struct {
    uint32_t hostKeyTypeLen;
    unsigned char *hostKeyType;
    uint32_t publicKeyLen;
    unsigned char *publicKey;
    
    uint32_t fLen;
    unsigned char *f;

    uint32_t hostSigLen;
    uint32_t hostSigTypeLen;
    unsigned char *hostSigType;
    size_t hostSigDataLen;
    unsigned char *hostSigData; 
} ServerDHResponse;

/*
Input: Pointer to a RawByteArray struct that contains the payload data and size
Output: A struct containing the raw bytes of the packet in Binary Packet Protocol format, and 
        the size of the packet
*/
RawByteArray *constructPacket(RawByteArray *payload);

/*
Input: None (potentially a list of algorithms in the future)
Output: A RawByteArray struct containing the payload and the size
*/
RawByteArray *constructKexPayload();

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
Input: The socket to send the protocol packet to
Output: 
*/
int sendKexInit (int sock);

/*
Input: A host and port number to connect to 
Output: SOME ERROR CODES - NEED TO UPDATE
*/
int start_client(const char *host, const int port);
