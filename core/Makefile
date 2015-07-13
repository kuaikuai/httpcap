
CC		= gcc
CCFLAGS  	= -Wall -I/usr/include/pcap -I/usr/local/include/pcap
DEBUGFLAGS	= -O0 -Wall -g -DDEBUG -I/usr/include/pcap -I/usr/local/include/pcap
LIBS		= -lpcap -ljemalloc -lm -pthread
PROG		= httpcap23
FILES		= cap.c  utils.c stats.c slab.c

.PHONY: all debug clean

all: $(PROG)

$(PROG): $(FILES)
	$(CC) $(CCFLAGS) -o $(PROG) $(FILES) $(LIBS)

debug: $(FILES)
	@echo "--------------------------------------------------"
	@echo "Compiling $(PROG) in debug mode"
	@echo "--------------------------------------------------"
	@echo ""
	$(CC) $(DEBUGFLAGS) -o $(PROG) $(FILES) $(LIBS)


clean:
	rm -f $(PROG)
