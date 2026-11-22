#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
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
static void fuse_lookup_status(int error)
{
    uint32_t status = error;
    (void)send(6, &status, sizeof(status), MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void fuse_lookup_fail(const char *operation)
{
    int error = errno ? errno : EIO;
    fuse_lookup_status(error);
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
    uint32_t status = 0;
    struct iovec fragments[] = {
        {&status, sizeof(status)},
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
    fuse_lookup_check((int)sendmsg(6, &reply, MSG_DONTWAIT | MSG_NOSIGNAL), "send pinned target");
}

static void fuse_lookup_requester_alive(void)
{
    struct pollfd request = {.fd = 3, .events = POLLIN};
    int ready;
    do {
        ready = poll(&request, 1, 0);
    } while (ready < 0 && errno == EINTR);
    fuse_lookup_check(ready, "poll requester pidfd");
    if (ready) {
        errno = ESRCH;
        fuse_lookup_fail("requester exited");
    }
}

/* Return false for requests that this additive, single-mount API cannot
 * faithfully apply. Never clear an existing security restriction. */
static bool fuse_lookup_readonly_attrs(uint32_t flags, struct mount_attr *attrs)
{
    const uint32_t atime = MS_NOATIME | MS_RELATIME | MS_STRICTATIME;
    const uint32_t required = MS_BIND | MS_REMOUNT | MS_RDONLY;
    const uint32_t supported = required | MS_REC | MS_SILENT | atime |
        MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NODIRATIME;
    if ((flags & required) != required || (flags & ~supported))
        return false;

    attrs->attr_set = MOUNT_ATTR_RDONLY;
    if (flags & MS_NOSUID)
        attrs->attr_set |= MOUNT_ATTR_NOSUID;
    if (flags & MS_NODEV)
        attrs->attr_set |= MOUNT_ATTR_NODEV;
    if (flags & MS_NOEXEC)
        attrs->attr_set |= MOUNT_ATTR_NOEXEC;
    if (flags & MS_NODIRATIME)
        attrs->attr_set |= MOUNT_ATTR_NODIRATIME;
    if (flags & atime)
        attrs->attr_clr = MOUNT_ATTR__ATIME;
    switch (flags & atime) {
    case MS_NOATIME:
        attrs->attr_set |= MOUNT_ATTR_NOATIME;
        break;
    case MS_STRICTATIME:
        attrs->attr_set |= MOUNT_ATTR_STRICTATIME;
        break;
    case MS_RELATIME:
    case 0:
        break;
    default:
        return false;
    }
    return true;
}

static int fuse_lookup_validate_type(const char *filesystem, mode_t mode)
{
    if ((strcmp(filesystem, "proc") == 0 || strcmp(filesystem, "sysfs") == 0) &&
        !S_ISDIR(mode))
        return ENOTDIR;
    return 0;
}

static int fuse_lookup_validate_identity(const struct statx *original,
                                         const struct statx *current)
{
    if (!(original->stx_mask & STATX_MNT_ID) || !(current->stx_mask & STATX_MNT_ID))
        return ENOTSUP;
    if (original->stx_mnt_id != current->stx_mnt_id ||
        original->stx_ino != current->stx_ino || original->stx_mode != current->stx_mode)
        return ESTALE;
    return 0;
}

static int lookup_fuse_target(int argc, char **argv)
{
    if (geteuid() != 0 || argc < 13) {
        errno = EPERM;
        fuse_lookup_fail("trusted launcher");
    }
    pid_t launcher = getppid();
    fuse_lookup_check(prctl(PR_SET_PDEATHSIG, SIGKILL), "parent death");
    alarm(12);

    char path[PATH_MAX];
    ssize_t length = recv(6, path, sizeof(path), MSG_TRUNC);
    if (length < 0)
        fuse_lookup_fail("receive target path");
    if (length == 0 || length >= PATH_MAX || memchr(path, '\0', length)) {
        errno = EINVAL;
        fuse_lookup_fail("target path message");
    }
    path[length] = '\0';

    uid_t uid[4];
    gid_t gid[4];
    for (int i = 0; i < 4; ++i) {
        uid[i] = fuse_lookup_decimal(argv[3 + i]);
        gid[i] = fuse_lookup_decimal(argv[7 + i]);
    }
    struct __user_cap_data_struct capabilities[2] = {0};
    for (int i = 0; i < 2; ++i) {
        capabilities[i].effective = fuse_lookup_decimal(argv[11 + i]);
        capabilities[i].permitted = capabilities[i].effective;
    }
    size_t group_count = (size_t)(argc - 13);
    gid_t *groups = calloc(group_count ? group_count : 1, sizeof(*groups));
    if (!groups)
        fuse_lookup_fail("allocate supplementary groups");
    for (size_t i = 0; i < group_count; ++i)
        groups[i] = fuse_lookup_decimal(argv[13 + i]);
    fuse_lookup_check(setgroups(group_count, groups), "set supplementary groups");
    free(groups);

    int proc_fd = open("/proc/self/fd", O_PATH | O_DIRECTORY | O_CLOEXEC);
    fuse_lookup_check(proc_fd, "pin helper proc descriptors");
    fuse_lookup_check(prctl(PR_SET_DUMPABLE, 0), "disable ptrace before namespace entry");
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
    if (path[0] != '/')
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
        if (!fuse_lookup_readonly_attrs(fuse_lookup_decimal(argv[2]), &attrs)) {
            errno = EINVAL;
            fuse_lookup_fail("unsupported readonly remount flags");
        }
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
        fuse_lookup_requester_alive();
        fuse_lookup_check((int)syscall(SYS_mount_setattr, 7, "", AT_EMPTY_PATH,
                                      &attrs, sizeof(attrs)),
                          "set pinned mount attribute");
        fuse_lookup_status(0);
        return 0;
    }
    if (strcmp(argv[1], "detach") == 0) {
        /* The launcher has verified FD 5 is the caller's non-shared old root
         * mount. "." uses this pinned cwd in the requester mount namespace. */
        fuse_lookup_requester_alive();
        fuse_lookup_check(umount2(".", MNT_DETACH), "detach previous root");
        fuse_lookup_status(0);
        return 0;
    }

    /* O_PATH performs the lookup without reading or invoking anything from
     * the caller's filesystem. Procfd targets were duplicated from its
     * file table and keep their original identity. */
    struct open_how how = {.flags = O_PATH | O_CLOEXEC,
                           .resolve = RESOLVE_NO_MAGICLINKS};
    int target = 7;
    if (strcmp(argv[1], "path") == 0) {
        target = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
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
    int validation = fuse_lookup_validate_type(argv[2], identity.stx_mode);
    if (validation) {
        errno = validation;
        fuse_lookup_fail("protected mount target directory");
    }
    char name[24];
    snprintf(name, sizeof(name), "%d", target);
    char resolved[PATH_MAX + 1];
    length = readlinkat(proc_fd, name, resolved, sizeof(resolved));
    if (length < 0)
        fuse_lookup_fail("read pinned target name");
    if (length == 0 || length >= PATH_MAX || resolved[0] != '/') {
        errno = EXDEV;
        fuse_lookup_fail("target outside requester root");
    }
    resolved[length] = '\0';
    if (strcmp(argv[1], "fd") == 0 && strcmp(resolved, path) != 0) {
        errno = ESTALE;
        fuse_lookup_fail("procfd changed before authorization");
    }
    int selected = (int)syscall(SYS_openat2, AT_FDCWD, resolved, &how, sizeof(how));
    fuse_lookup_check(selected, "find pinned target in requester root");
    struct statx current;
    fuse_lookup_check((int)syscall(SYS_statx, selected, "", AT_EMPTY_PATH | AT_STATX_FORCE_SYNC,
                        STATX_TYPE | STATX_INO | STATX_MNT_ID, &current),
          "stat selected pathname");
    validation = fuse_lookup_validate_identity(&identity, &current);
    if (validation) {
        errno = validation;
        fuse_lookup_fail("validate selected target");
    }
    fuse_lookup_send_target(target, resolved, identity.stx_mnt_id);
    return 0;
}
