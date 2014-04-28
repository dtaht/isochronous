CFLAGS+=-std=gnu99
LDFLAGS+=-lrt -lm
PROGS=udpburst isoping

all: $(PROGS)

udpburst: udpburst.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping: isoping.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(PROGS)
