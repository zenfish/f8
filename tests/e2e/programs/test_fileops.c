/*
 * test_fileops.c - Deterministic file operation sequence for mactrace testing.
 *
 * Creates a temp file, writes known data, reads it back, verifies, unlinks.
 * Expected syscalls: open(O_CREAT|O_WRONLY) → write(13 bytes) → close →
 *                    open(O_RDONLY) → read(13 bytes) → close → unlink
 *
 * Exit code 0 = success, non-zero = verification failure.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_FILE "/tmp/mactrace_test_fileops.tmp"
#define TEST_DATA "Hello mactrace"
#define TEST_LEN  14

int main(void) {
    char buf[64];
    int fd;
    ssize_t n;

    /* Write phase */
    fd = open(TEST_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open write"); return 1; }
    n = write(fd, TEST_DATA, TEST_LEN);
    if (n != TEST_LEN) { perror("write"); return 2; }
    close(fd);

    /* Read phase */
    fd = open(TEST_FILE, O_RDONLY);
    if (fd < 0) { perror("open read"); return 3; }
    n = read(fd, buf, sizeof(buf));
    if (n != TEST_LEN) { fprintf(stderr, "read: expected %d, got %zd\n", TEST_LEN, n); return 4; }
    close(fd);

    /* Verify */
    if (memcmp(buf, TEST_DATA, TEST_LEN) != 0) {
        fprintf(stderr, "data mismatch\n");
        return 5;
    }

    /* Cleanup */
    unlink(TEST_FILE);
    return 0;
}
