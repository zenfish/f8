/*
 * test_forkexec.c - Deterministic fork/exec for f8 testing.
 *
 * Forks a child that execs /bin/echo "f8_test_output", parent waits.
 * Expected: fork → (child) execve("/bin/echo") → write("f8_test_output\n")
 *           → exit(0) → (parent) wait4 → exit(0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child: exec echo */
        execl("/bin/echo", "echo", "f8_test_output", NULL);
        perror("execl");
        _exit(127);
    }

    /* Parent: wait for child */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 2;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child exited abnormally: %d\n", status);
        return 3;
    }

    return 0;
}
