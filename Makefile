CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

SRC = src/main.c src/packet_capture.c src/packet_analysis.c
INCLUDE = -Iinclude

OBJS = $(SRC:.c=.o)

all: analyzer

analyzer: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o analyzer $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f $(OBJS) analyzer
