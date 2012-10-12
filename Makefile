# Tested on Ubuntu 10.04 and Cygwin
CC=gcc
CFLAGS=-c -Wall
LDFLAGS= -lcrypto -lssl

all: clean test_client

test_client: test_client.o openssl_hostname_validation.o
	$(CC) test_client.o openssl_hostname_validation.o -o test_client $(LDFLAGS)

test_client.o: test_client.c
	$(CC) $(CFLAGS) test_client.c

openssl_hostname_validation.o: openssl_hostname_validation.c
	$(CC) $(CFLAGS) openssl_hostname_validation.c

clean:
	rm -rf *o test_client.exe