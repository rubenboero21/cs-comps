# README

## client.c

Written by Liam and Ruben for Fall 2024 CS Comps with Jeff Ondich. More information about the project can be found [here](https://docs.google.com/document/d/e/2PACX-1vSouRo8KV3OQYULsrzRG4ekcRslUbjvLqcGHJjQ8peiBg_xVDK24utqCMxEoJRkYdpKWsjdgJuT5ZX9/pub)

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
client.c depends on the openSSL library. 
To install the ossl library, use the package manager of your choice. For example:
* Using Homebrew on Mac: `brew install openssl@3`
* Using apt on Ubuntu: `sudo apt install openssl`

## How to run the code
* Use the Makefile (see above). If your specific setup is not handled in the Makefile, you may need to modify the Makefile. Currently supported setups:
  * arm Mac with openssl@3 installed via Homebrew
  * LIAMS LINUX SETUP
* Compile and run the code yourself:
  * Compile: gcc `<any additional flags for your ossl install>` -lssl -lcrypto -o `<output file name>` client.c
  * Run: ./`<output file name>` `<hostname>` `<port number>`
