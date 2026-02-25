/*
 * test_network.c - Deterministic network ops for mactrace testing.
 *
 * Creates a TCP socket, connects to localhost:1 (guaranteed ECONNREFUSED
 * since port 1 is privileged and nothing listens there), then cleans up.
 * Expected: socket(AF_INET, SOCK_STREAM) → connect(127.0.0.1:1, errno=ECONNREFUSED)
 *           → close
 *
 * Exit code 0 = success (connection refused is the expected outcome).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);  /* Port 1 — guaranteed ECONNREFUSED */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) {
        fprintf(stderr, "connect succeeded unexpectedly\n");
        close(fd);
        return 2;
    }

    if (errno != ECONNREFUSED) {
        fprintf(stderr, "expected ECONNREFUSED, got %s\n", strerror(errno));
        close(fd);
        return 3;
    }

    close(fd);
    return 0;
}
