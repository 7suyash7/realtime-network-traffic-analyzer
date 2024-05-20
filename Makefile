CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
LDFLAGS = -lpcap -lncurses

SRC = src/main.o src/packet_capture.o src/packet_analysis.o src/dashboard.o src/logger.o
OBJ = $(SRC)

all: analyzer

analyzer: $(OBJ)
	$(CC) $(OBJ) -o analyzer $(LDFLAGS)

src/main.o: src/main.c
	$(CC) $(CFLAGS) -c src/main.c -o src/main.o

src/packet_capture.o: src/packet_capture.c
	$(CC) $(CFLAGS) -c src/packet_capture.c -o src/packet_capture.o

src/packet_analysis.o: src/packet_analysis.c
	$(CC) $(CFLAGS) -c src/packet_analysis.c -o src/packet_analysis.o

src/dashboard.o: src/dashboard.c
	$(CC) $(CFLAGS) -c src/dashboard.c -o src/dashboard.o

src/logger.o: src/logger.c
	$(CC) $(CFLAGS) -c src/logger.c -o src/logger.o

clean:
	rm -f $(OBJ) analyzer
