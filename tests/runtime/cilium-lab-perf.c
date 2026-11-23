#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
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

/* A native per-thread perf request that does not need a delegated event. */
static int ordinary_perf(void)
{
    struct perf_event_attr attr = {
        .size = sizeof(attr),
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_TASK_CLOCK,
        .exclude_kernel = 1,
    };
    int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1,
                          PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        return errno;
    close(fd);
    return 0;
}

/* The host supplies only this fixed, unattached feature probe. */
static int send_jit_fd(int socket_fd)
{
    struct bpf_insn program[] = {{.code = 0xb7}, {.code = 0x95}};
    union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = sizeof(program) / sizeof(program[0]),
        .insns = (uintptr_t)program,
        .license = (uintptr_t)"Apache-2.0",
    };
    int prog = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &load, sizeof(load));
    if (prog < 0) {
        perror("load sandbox test probe");
        return 2;
    }
    char data = 'J';
    struct iovec iov = {.iov_base = &data, .iov_len = sizeof(data)};
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(prog))];
    } control = {0};
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(prog));
    memcpy(CMSG_DATA(cmsg), &prog, sizeof(prog));
    int ret = sendmsg(socket_fd, &msg, 0) == 1 ? 0 : 2;
    close(prog);
    return ret;
}

static int receive_jit_fd(void)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX, .sun_path = "/jit-probe.sock"};
    int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0)
        return -1;
    int prog = -1;
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        char value;
        struct iovec iov = {.iov_base = &value, .iov_len = sizeof(value)};
        union {
            struct cmsghdr align;
            char bytes[CMSG_SPACE(sizeof(prog))];
        } control = {0};
        struct msghdr msg = {
            .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
        };
        if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) == 1 && value == 'J') {
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                cmsg->cmsg_len == CMSG_LEN(sizeof(prog)))
                memcpy(&prog, CMSG_DATA(cmsg), sizeof(prog));
        }
    }
    close(socket_fd);
    return prog;
}

static void jit_probe(int prog, int unsupported)
{
    // The kernel ignores this input scalar when filling program info. The
    // narrow Sysbox probe expects a zeroed input buffer and must pass it on.
    struct bpf_prog_info info = {.type = unsupported ? UINT32_MAX : 0};
    union bpf_attr query = {
        .info.bpf_fd = prog,
        .info.info_len = sizeof(info),
        .info.info = (uintptr_t)&info,
    };
    if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) != 0) {
        printf("%d\n", errno);
        return;
    }
    if (info.type != BPF_PROG_TYPE_SOCKET_FILTER || info.jited_prog_insns != 0 ||
        info.xlated_prog_insns != 0) {
        puts("-1");
        return;
    }
    // Program IDs differ across runs. Record whether the ID is visible.
    printf("0 %u %d %u %u", info.type, info.id != 0,
           info.jited_prog_len, info.xlated_prog_len);
    for (size_t i = 0; i < sizeof(info.tag); ++i)
        printf(" %u", (unsigned int)info.tag[i]);
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--send-jit-fd") == 0)
        return send_jit_fd(atoi(argv[2]));
    if (argc != 1)
        return 2;
    int prog = receive_jit_fd();
    if (prog < 0)
        return 2;
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        if (strcmp(command, "jit\n") == 0) {
            jit_probe(prog, 0);
        } else if (strcmp(command, "jit-unsupported\n") == 0) {
            jit_probe(prog, 1);
        } else if (strcmp(command, "probe\n") == 0) {
            printf("%d\n", probe(0));
        } else if (strcmp(command, "out-of-policy\n") == 0) {
            printf("%d\n", probe(1));
        } else if (strcmp(command, "ordinary-perf\n") == 0) {
            printf("%d\n", ordinary_perf());
        } else {
            return 2;
        }
        if (fflush(stdout) != 0)
            return 2;
    }
    close(prog);
    return ferror(stdin) ? 2 : 0;
}
