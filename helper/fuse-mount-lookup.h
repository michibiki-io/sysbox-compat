#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Task data and namespace descriptors are acquired by the trusted launcher.
 * 3 thread pidfd, 4 requester root, 5 requester cwd, 6 reply socket,
 * 7 requester target FD for a procfd request (otherwise absent). */
static void fuse_lookup_fail(const char *operation)
{
    int error = errno ? errno : EIO;
    fprintf(stderr, "FUSE target: %s: %s\n", operation, strerror(error));
    _exit(error < 256 ? error : EIO);
}

static void fuse_lookup_check(int result, const char *operation)
{
    if (result < 0)
        fuse_lookup_fail(operation);
}

static uint32_t fuse_lookup_decimal(const char *value)
{
    char *end;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno || end == value || *end || parsed > UINT32_MAX) {
        errno = EINVAL;
        fuse_lookup_fail("invalid credential");
    }
    return parsed;
}

static void fuse_lookup_send_target(int target, const char *path, uint64_t mount_id)
{
    char ancillary[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec fragments[] = {
        {&mount_id, sizeof(mount_id)},
        {(void *)path, strlen(path)},
    };
    struct msghdr reply = {
        .msg_iov = fragments,
        .msg_iovlen = sizeof(fragments) / sizeof(fragments[0]),
        .msg_control = ancillary,
        .msg_controllen = sizeof(ancillary),
    };
    struct cmsghdr *rights = CMSG_FIRSTHDR(&reply);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(target));
    memcpy(CMSG_DATA(rights), &target, sizeof(target));
    fuse_lookup_check((int)sendmsg(6, &reply, MSG_NOSIGNAL), "send pinned target");
}

static int lookup_fuse_target(int argc, char **argv)
{
    if (geteuid() != 0 || argc < 14) {
        errno = EPERM;
        fuse_lookup_fail("trusted launcher");
    }
    pid_t launcher = getppid();
    fuse_lookup_check(prctl(PR_SET_PDEATHSIG, SIGKILL), "parent death");
    alarm(12);

    uid_t uid[4];
    gid_t gid[4];
    for (int i = 0; i < 4; ++i) {
        uid[i] = fuse_lookup_decimal(argv[4 + i]);
        gid[i] = fuse_lookup_decimal(argv[8 + i]);
    }
    struct __user_cap_data_struct capabilities[2] = {0};
    for (int i = 0; i < 2; ++i) {
        capabilities[i].effective = fuse_lookup_decimal(argv[12 + i]);
        capabilities[i].permitted = capabilities[i].effective;
    }
    size_t group_count = (size_t)(argc - 14);
    gid_t *groups = calloc(group_count ? group_count : 1, sizeof(*groups));
    if (!groups)
        fuse_lookup_fail("allocate supplementary groups");
    for (size_t i = 0; i < group_count; ++i)
        groups[i] = fuse_lookup_decimal(argv[14 + i]);
    fuse_lookup_check(setgroups(group_count, groups), "set supplementary groups");
    free(groups);

    int proc_fd = open("/proc/self/fd", O_PATH | O_DIRECTORY | O_CLOEXEC);
    fuse_lookup_check(proc_fd, "pin helper proc descriptors");
    fuse_lookup_check(setns(3, CLONE_NEWUSER | CLONE_NEWNS), "enter requester namespaces");
    fuse_lookup_check(prctl(PR_SET_KEEPCAPS, 1), "retain capabilities for credential setup");
    fuse_lookup_check(setresgid(gid[0], gid[1], gid[2]), "set requester GIDs");
    fuse_lookup_check(setresuid(uid[0], uid[1], uid[2]), "set requester UIDs");
    /* uid changes may clear effective capabilities. Restore what credential
     * setup needs, then install the filesystem IDs before the first lookup
     * through the requester's root or cwd. Either may already be on FUSE. */
    const uint32_t cred_setup = (1U << CAP_SETUID) | (1U << CAP_SETGID);
    const uint32_t root_setup = 1U << CAP_SYS_CHROOT;
    struct __user_cap_data_struct setup[2] = {
        {.effective = cred_setup,
         .permitted = capabilities[0].permitted | cred_setup | root_setup},
        {.permitted = capabilities[1].permitted},
    };
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    fuse_lookup_check((int)syscall(SYS_capset, &header, setup), "set credential setup capabilities");
    setfsgid(gid[3]);
    setfsuid(uid[3]);
    if ((uid_t)setfsuid((uid_t)-1) != uid[3] || (gid_t)setfsgid((gid_t)-1) != gid[3]) {
        errno = EPERM;
        fuse_lookup_fail("set filesystem credentials");
    }
    setup[0].effective = capabilities[0].effective | root_setup;
    setup[1].effective = capabilities[1].effective;
    fuse_lookup_check((int)syscall(SYS_capset, &header, setup), "set root setup capabilities");
    fuse_lookup_check(fchdir(4), "select requester root");
    fuse_lookup_check(chroot("."), "set requester root");
    if (argv[2][0] != '/')
        fuse_lookup_check(fchdir(5), "select requester cwd");

    fuse_lookup_check((int)syscall(SYS_capset, &header, capabilities), "set requester capabilities");
    fuse_lookup_check(prctl(PR_SET_PDEATHSIG, SIGKILL), "restore parent death");
    if (getppid() != launcher) {
        errno = ESRCH;
        fuse_lookup_fail("launcher exited");
    }
    fuse_lookup_check(prctl(PR_SET_DUMPABLE, 0), "disable ptrace");

    struct mount_attr attrs = {0};
    if (strcmp(argv[1], "readonly") == 0) {
        attrs.attr_set = MOUNT_ATTR_RDONLY;
    } else if (strcmp(argv[1], "noatime") == 0) {
        attrs.attr_set = MOUNT_ATTR_NOATIME;
        attrs.attr_clr = MOUNT_ATTR__ATIME;
    } else if (strcmp(argv[1], "relatime") == 0) {
        attrs.attr_set = MOUNT_ATTR_RELATIME;
        attrs.attr_clr = MOUNT_ATTR__ATIME;
    } else if (strcmp(argv[1], "strictatime") == 0) {
        attrs.attr_set = MOUNT_ATTR_STRICTATIME;
        attrs.attr_clr = MOUNT_ATTR__ATIME;
    }
    if (attrs.attr_set || attrs.attr_clr) {
        fuse_lookup_check((int)syscall(SYS_mount_setattr, 7, "", AT_EMPTY_PATH,
                                      &attrs, sizeof(attrs)),
                          "set pinned mount attribute");
        return 0;
    }
    if (strcmp(argv[1], "detach") == 0) {
        /* The launcher has verified FD 5 is the caller's non-shared old root
         * mount. "." uses this pinned cwd in the requester mount namespace. */
        fuse_lookup_check(umount2(".", MNT_DETACH), "detach previous root");
        return 0;
    }

    /* O_PATH performs the lookup without reading or invoking anything from
     * the caller's filesystem. Procfd targets were duplicated from its
     * file table and keep their original identity. */
    struct open_how how = {.flags = O_PATH | O_CLOEXEC,
                           .resolve = RESOLVE_NO_MAGICLINKS};
    int target = 7;
    if (strcmp(argv[1], "path") == 0) {
        target = (int)syscall(SYS_openat2, AT_FDCWD, argv[2], &how, sizeof(how));
        fuse_lookup_check(target, "open requester target");
    } else if (strcmp(argv[1], "fd") == 0) {
        int proc = (int)syscall(SYS_openat2, AT_FDCWD, "/proc", &how, sizeof(how));
        fuse_lookup_check(proc, "open requester proc");
        struct statfs procfs;
        fuse_lookup_check(fstatfs(proc, &procfs), "requester proc filesystem");
        close(proc);
        if (procfs.f_type != PROC_SUPER_MAGIC) {
            errno = EXDEV;
            fuse_lookup_fail("requester proc filesystem type");
        }
    } else {
        errno = EINVAL;
        fuse_lookup_fail("target type");
    }

    struct statx identity;
    fuse_lookup_check((int)syscall(SYS_statx, target, "", AT_EMPTY_PATH | AT_STATX_FORCE_SYNC,
                        STATX_TYPE | STATX_INO | STATX_MNT_ID, &identity),
          "stat requester target");
    if ((strcmp(argv[3], "proc") == 0 || strcmp(argv[3], "sysfs") == 0) && !S_ISDIR(identity.stx_mode)) {
        errno = ENOTDIR;
        fuse_lookup_fail("protected mount target directory");
    }
    if (!(identity.stx_mask & STATX_MNT_ID)) {
        errno = ENOTSUP;
        fuse_lookup_fail("target mount identity");
    }

    char name[24];
    snprintf(name, sizeof(name), "%d", target);
    char resolved[PATH_MAX + 1];
    ssize_t length = readlinkat(proc_fd, name, resolved, sizeof(resolved));
    if (length < 0)
        fuse_lookup_fail("read pinned target name");
    if (length == 0 || length >= PATH_MAX || resolved[0] != '/') {
        errno = EXDEV;
        fuse_lookup_fail("target outside requester root");
    }
    resolved[length] = '\0';
    if (strcmp(argv[1], "fd") == 0 && strcmp(resolved, argv[2]) != 0) {
        errno = ESTALE;
        fuse_lookup_fail("procfd changed before authorization");
    }
    int selected = (int)syscall(SYS_openat2, AT_FDCWD, resolved, &how, sizeof(how));
    fuse_lookup_check(selected, "find pinned target in requester root");
    struct statx current;
    fuse_lookup_check((int)syscall(SYS_statx, selected, "", AT_EMPTY_PATH | AT_STATX_FORCE_SYNC,
                        STATX_TYPE | STATX_INO | STATX_MNT_ID, &current),
          "stat selected pathname");
    if (identity.stx_mnt_id != current.stx_mnt_id || identity.stx_ino != current.stx_ino ||
        identity.stx_mode != current.stx_mode) {
        errno = ESTALE;
        fuse_lookup_fail("target changed");
    }
    fuse_lookup_send_target(target, resolved, identity.stx_mnt_id);
    return 0;
}
