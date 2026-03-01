/*
 * test_udp_io.c — Deterministic UDP I/O for mactrace --capture-io testing.
 *
 * Sends a known payload via sendto() to a loopback UDP socket, then
 * receives it back via recvfrom(). This exercises the network IO capture
 * path (sendto/recvfrom) with known data we can assert on.
 *
 * Exit code 0 = success.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PAYLOAD      "MACTRACE_UDP_TEST_DATA"
#define PAYLOAD_LEN  22

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    /* Bind to ephemeral port on loopback */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;  /* kernel picks a port */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return 2;
    }

    /* Get the assigned port */
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) < 0) {
        perror("getsockname"); close(fd); return 3;
    }

    /* Send to ourselves */
    ssize_t ns = sendto(fd, PAYLOAD, PAYLOAD_LEN, 0,
                        (struct sockaddr *)&addr, sizeof(addr));
    if (ns != PAYLOAD_LEN) {
        fprintf(stderr, "sendto: expected %d, got %zd\n", PAYLOAD_LEN, ns);
        close(fd); return 4;
    }

    /* Receive it back */
    char buf[64];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t nr = recvfrom(fd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&from, &flen);
    if (nr != PAYLOAD_LEN) {
        fprintf(stderr, "recvfrom: expected %d, got %zd\n", PAYLOAD_LEN, nr);
        close(fd); return 5;
    }

    /* Verify */
    if (memcmp(buf, PAYLOAD, PAYLOAD_LEN) != 0) {
        fprintf(stderr, "data mismatch\n");
        close(fd); return 6;
    }

    close(fd);
    return 0;
}
