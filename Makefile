CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=-lssl -lcrypto -lpthread
SOURCES=addr_miner.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=mine_addr
RM=rm -f

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) $(EXECUTABLE)
	$(RM) $(OBJECTS)
