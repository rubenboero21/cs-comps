OS := $(shell uname)
CPU := $(shell uname -p)
CFLAGS = -Wall -Wno-deprecated-declarations -lssl -lcrypto

# Flags for compilation on MacOS using Arm CPU and OpenSSL installation via Homebrew
# OSSL install via apt on x86_64 Linux does not require these additional CFLAGS
ifeq ($(OS), Darwin)
	ifeq ($(CPU), arm)
		CFLAGS += -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib
	endif
endif

# Compile and run the program
run: client
	./client $(ARGS)

# Just compile the program
compile: client

# Rule for creating the executable
a.out: client.c
	gcc $(CFLAGS) -o client client.c

# Clean up the generated files
clean:
	rm -f client
