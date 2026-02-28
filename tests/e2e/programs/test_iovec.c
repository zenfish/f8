/*
 * test_iovec.c — Deterministic vectored I/O test for mactrace --iovec.
 *
 * Tests: writev (3 buffers), readv (3 buffers), truncation case (6 buffers).
 * All data is deterministic for assertion in tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

#define WRITEV_BUF0 "HEAD"
#define WRITEV_BUF1 "BODY"
#define WRITEV_BUF2 "TAIL"
#define WRITEV_TOTAL 12  /* 4 + 4 + 4 */

#define TRUNC_BUFS 6
#define TRUNC_EACH 2
#define TRUNC_TOTAL 12  /* 6 * 2 */

int main(void) {
    int pfd[2];

    /* ── Test 1: writev with 3 buffers ── */
    if (pipe(pfd) < 0) { perror("pipe"); return 1; }

    struct iovec wv[3];
    wv[0].iov_base = WRITEV_BUF0; wv[0].iov_len = 4;
    wv[1].iov_base = WRITEV_BUF1; wv[1].iov_len = 4;
    wv[2].iov_base = WRITEV_BUF2; wv[2].iov_len = 4;

    ssize_t nw = writev(pfd[1], wv, 3);
    if (nw != WRITEV_TOTAL) { fprintf(stderr, "writev: expected %d, got %zd\n", WRITEV_TOTAL, nw); return 1; }
    close(pfd[1]);

    /* ── Test 2: readv the same data back with 3 buffers ── */
    char rb0[4], rb1[4], rb2[4];
    struct iovec rv[3];
    rv[0].iov_base = rb0; rv[0].iov_len = 4;
    rv[1].iov_base = rb1; rv[1].iov_len = 4;
    rv[2].iov_base = rb2; rv[2].iov_len = 4;

    ssize_t nr = readv(pfd[0], rv, 3);
    if (nr != WRITEV_TOTAL) { fprintf(stderr, "readv: expected %d, got %zd\n", WRITEV_TOTAL, nr); return 1; }
    close(pfd[0]);

    /* Verify data integrity */
    if (memcmp(rb0, WRITEV_BUF0, 4) || memcmp(rb1, WRITEV_BUF1, 4) || memcmp(rb2, WRITEV_BUF2, 4)) {
        fprintf(stderr, "readv: data mismatch\n");
        return 1;
    }

    /* ── Test 3: writev with 6 buffers (truncation test for --iovec 4) ── */
    if (pipe(pfd) < 0) { perror("pipe"); return 1; }

    char *tbufs[] = {"AA", "BB", "CC", "DD", "EE", "FF"};
    struct iovec tv[TRUNC_BUFS];
    for (int i = 0; i < TRUNC_BUFS; i++) {
        tv[i].iov_base = tbufs[i];
        tv[i].iov_len = TRUNC_EACH;
    }

    ssize_t nt = writev(pfd[1], tv, TRUNC_BUFS);
    if (nt != TRUNC_TOTAL) { fprintf(stderr, "writev6: expected %d, got %zd\n", TRUNC_TOTAL, nt); return 1; }
    close(pfd[1]);

    /* Drain the pipe */
    char drain[TRUNC_TOTAL];
    read(pfd[0], drain, sizeof(drain));
    close(pfd[0]);

    return 0;
}
