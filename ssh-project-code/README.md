# README

## client.c

Written by Liam and Ruben for Fall CS Comps with Jeff Ondich

client.c is a simple ssh client that runs on the command line. The usage is:

```makefile
./<executable> <hostname> <port number>
```

## How to use the Makefile

Just compile the code:

```makefile
make compile
```

Compile and run the code:

```makefile
make ARGS="<hostname> <port number>"
```

Example:

```makefile
make ARGS="192.168.64.6 22"
```

Clean up created files:

```makefile
make clean
```
## Dependencies
This code depends on the openSSL library. 

## How to run the code
* Use the Makefile (see above), modifying the CFLAGS to match your specific installation of the openSSL library
* Compile and run the code yourself:
  * Compile: gcc <any additional flags for your ossl install> -lssl -lcrypto -o <output file name> client.c
  * Run: ./<output file name>
