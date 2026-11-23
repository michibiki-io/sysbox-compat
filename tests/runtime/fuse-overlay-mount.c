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
    } else if (argc == 3 &&
               (strcmp(argv[1], "proc-fd") == 0 || strcmp(argv[1], "sys-fd") == 0 ||
                strcmp(argv[1], "proc-bad-fd") == 0)) {
        int invalid = strcmp(argv[1], "proc-bad-fd") == 0;
        const char *filesystem = strcmp(argv[1], "sys-fd") == 0 ? "sysfs" : "proc";
        int target = open(argv[2], O_PATH | O_CLOEXEC | (invalid ? 0 : O_DIRECTORY));
        if (target < 0) {
            perror("open protected mount target");
            return 1;
        }
        char target_path[64];
        snprintf(target_path, sizeof(target_path), "/proc/thread-self/fd/%d", target);
        int rc = mount(filesystem, target_path, filesystem, MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
        if ((!invalid && rc == 0) || (invalid && rc < 0 && errno == ENOTDIR))
            return 0;
        if (rc == 0) {
            fprintf(stderr, "mount unexpectedly accepted a non-directory target\n");
            return 1;
        }
    } else {
        fprintf(stderr, "usage: %s {private TARGET|{bind|missing|denied} SOURCE TARGET|{proc|proc-fd|proc-bad-fd|sys-fd} TARGET}\n", argv[0]);
        return 2;
    }

    int failure = errno;
    fprintf(stderr, "%s mount failed (errno %d): %s\n", argv[1], failure, strerror(failure));
    return 1;
}
