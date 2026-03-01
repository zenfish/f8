# Check for C compiler — skip gracefully if not found
CC := $(shell command -v cc 2>/dev/null || command -v gcc 2>/dev/null || command -v clang 2>/dev/null)
CFLAGS = -Wall -Wextra -O0 -g
PROGRAMS = test_fileops test_forkexec test_network test_iovec test_udp_io

ifeq ($(CC),)
all:
	@echo "SKIP: No C compiler found (cc/gcc/clang). E2E test programs not built."

else
all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<
endif

clean:
	rm -f $(PROGRAMS)

.PHONY: all clean
