CC = gcc
CFLAGS = -Wall

CFLAGS += -I include \
	    -D_FILE_OFFSET_BITS=64 \
	    -DSO_RXQ_OVFL=40 \
	    -DPF_CAN=29 \
	    -DAF_CAN=PF_CAN \
	    -D_GNU_SOURCE

TARGET = can-server
OBJECTS = candump.o lib.o

HEADERS = lib.h

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

candump.o: candump.c $(HEADERS)
	$(CC) $(CFLAGS) -c candump.c

lib.o: lib.c $(HEADERS)
	$(CC) $(CFLAGS) -c lib.c

clean:
	rm -rf *.o
	rm -f $(TARGET)
