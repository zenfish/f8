CC = cc
CFLAGS = -Wall -Wextra -O0 -g
PROGRAMS = test_fileops test_forkexec test_network

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)

.PHONY: all clean
