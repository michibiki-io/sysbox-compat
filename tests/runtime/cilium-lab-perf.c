#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int probe(int invalid)
{
    struct perf_event_attr attr = {
        .size = sizeof(attr),
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_type = invalid ? PERF_SAMPLE_TID : PERF_SAMPLE_RAW,
        .watermark = 1,
        .wakeup_watermark = 1,
    };
    int cpu = sched_getcpu();
    if (cpu < 0)
        return -1;
    int fd = (int)syscall(SYS_perf_event_open, &attr, -1, cpu, -1,
                          PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        return errno;

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        close(fd);
        return -1;
    }
    size_t size = 2 * (size_t)page;
    void *ring = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int valid = fcntl(fd, F_GETFD) == FD_CLOEXEC && ring != MAP_FAILED;
    if (ring != MAP_FAILED)
        munmap(ring, size);
    close(fd);
    return valid ? 0 : -1;
}

int main(void)
{
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        int invalid = strcmp(command, "out-of-policy\n") == 0;
        if (!invalid && strcmp(command, "probe\n") != 0)
            return 2;
        printf("%d\n", probe(invalid));
        if (fflush(stdout) != 0)
            return 2;
    }
    return ferror(stdin) ? 2 : 0;
}
