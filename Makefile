CFLAGS+=-std=gnu99 -g
LDFLAGS+=-lrt -lm
PROGS=udpburst isoping isostream

all: $(PROGS)

udpburst: udpburst.c dscp.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping: isoping.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isostream: isostream.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(PROGS)
