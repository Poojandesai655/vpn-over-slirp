# Makefile for vpn_server (with AES encryption + debug)

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -DDEBUG -I/usr/include/slirp -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
LDFLAGS = -lslirp -lglib-2.0

TARGET = vpn_server

SRCS = vpn_server.c aes_encrypt.c
OBJS = vpn_server.o aes_encrypt.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

vpn_server.o: vpn_server.c
	$(CC) $(CFLAGS) -c vpn_server.c

aes_encrypt.o: aes_encrypt.c
	$(CC) $(CFLAGS) -c aes_encrypt.c

clean:
	rm -f *.o $(TARGET)

