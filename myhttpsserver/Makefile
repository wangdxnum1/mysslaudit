# Makefile
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto

all: myhttpsserver

myhttpsserver: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f myhttpsserver

.PHONY: all clean