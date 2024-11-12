OS := $(shell uname)
CPU := $(shell uname -p)
CFLAGS = -Wall -Wno-deprecated-declarations -lssl -lcrypto

# Flags for compilation on MacOS using Arm CPU and OpenSSL installation via Homebrew
ifeq ($(OS), Darwin)
	ifeq ($(CPU), arm)
		CFLAGS += -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib
	endif
endif

# Compile and run the program
run: a.out
	./a.out $(ARGS)

# Just compile the program
compile: a.out

# Rule for creating the executable
a.out: client.c
	gcc $(CFLAGS) -o a.out client.c

# Clean up the generated files
clean:
	rm -f a.out
