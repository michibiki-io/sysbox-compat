#define _GNU_SOURCE
#include <assert.h>

#include "../../helper/fuse-mount-lookup.h"

int main(void)
{
    const uint32_t base = MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC;
    struct mount_attr attrs = {0};
    assert(fuse_lookup_readonly_attrs(base | MS_NOSUID | MS_NODEV | MS_NOEXEC |
                                    MS_NODIRATIME | MS_NOATIME, &attrs));
    assert(attrs.attr_set == (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                              MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC |
                              MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOATIME));
    assert(attrs.attr_clr == MOUNT_ATTR__ATIME);
    assert(!fuse_lookup_readonly_attrs(base | MS_SYNCHRONOUS, &attrs));
    assert(!fuse_lookup_readonly_attrs(base | MS_NOATIME | MS_RELATIME, &attrs));
    assert(!fuse_lookup_readonly_attrs(base & ~MS_BIND, &attrs));

    struct statx selected = {
        .stx_mask = STATX_MNT_ID | STATX_INO | STATX_TYPE | STATX_MODE,
        .stx_mnt_id = 17, .stx_ino = 31, .stx_mode = S_IFDIR | 0755,
    };
    assert(fuse_lookup_validate_type("proc", selected.stx_mode) == 0);
    assert(fuse_lookup_validate_type("sysfs", S_IFREG) == ENOTDIR);
    assert(fuse_lookup_validate_identity(&selected, &selected) == 0);
    struct statx replacement = selected;
    replacement.stx_ino++;
    assert(fuse_lookup_validate_identity(&selected, &replacement) == ESTALE);
    replacement = selected;
    replacement.stx_mnt_id++;
    assert(fuse_lookup_validate_identity(&selected, &replacement) == ESTALE);
    replacement.stx_mask &= ~STATX_MNT_ID;
    assert(fuse_lookup_validate_identity(&selected, &replacement) == ENOTSUP);
    return 0;
}
