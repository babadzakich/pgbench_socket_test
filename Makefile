CFLAGS ?= -O2 -Wall -Wextra -g

replay: replay.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

clean:
	rm -f replay
