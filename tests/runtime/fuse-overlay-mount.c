#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "private") == 0) {
        if (mount(NULL, argv[2], NULL, MS_PRIVATE, NULL) == 0)
            return 0;
    } else if (argc == 4 && strcmp(argv[1], "bind") == 0) {
        if (mount(argv[2], argv[3], NULL, MS_BIND, NULL) == 0)
            return 0;
    } else if (argc == 4 && strcmp(argv[1], "missing") == 0) {
        if (mount(argv[2], argv[3], NULL, MS_BIND, NULL) < 0 && errno == ENOENT)
            return 0;
    } else if (argc == 4 && strcmp(argv[1], "denied") == 0) {
        setfsuid(1001);
        if ((uid_t)setfsuid((uid_t)-1) != 1001) {
            fprintf(stderr, "could not set the probe filesystem UID\n");
            return 1;
        }
        if (mount(argv[2], argv[3], NULL, MS_BIND, NULL) < 0 && errno == EACCES)
            return 0;
    } else if (argc == 3 && strcmp(argv[1], "proc") == 0) {
        if (mount("proc", argv[2], "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0)
            return 0;
    } else if (argc == 3 && strcmp(argv[1], "proc-fd") == 0) {
        int target = open(argv[2], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (target < 0) {
            perror("open proc target");
            return 1;
        }
        char target_path[64];
        snprintf(target_path, sizeof(target_path), "/proc/thread-self/fd/%d", target);
        if (mount("proc", target_path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0)
            return 0;
    } else {
        fprintf(stderr, "usage: %s {private TARGET|{bind|missing|denied} SOURCE TARGET|{proc|proc-fd} TARGET}\n", argv[0]);
        return 2;
    }

    int failure = errno;
    fprintf(stderr, "%s mount failed (errno %d): %s\n", argv[1], failure, strerror(failure));
    return 1;
}
