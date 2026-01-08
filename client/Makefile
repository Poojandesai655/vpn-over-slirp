# Makefile for VPN Client and GUI

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = 

TARGET = vpn_client
TARGET_GUI = vpn_client_gui

SRCS = vpn_client.c aes_encrypt.c
OBJS = $(SRCS:.c=.o)

GTK_FLAGS = `pkg-config --cflags --libs gtk+-3.0`

all: $(TARGET) $(TARGET_GUI)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(TARGET_GUI): vpn_client_gui.c
	$(CC) $(CFLAGS) -o $@ vpn_client_gui.c $(GTK_FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET) $(TARGET_GUI)

