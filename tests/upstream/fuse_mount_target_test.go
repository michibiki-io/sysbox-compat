package seccomp

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFuseRequesterDescriptor(t *testing.T) {
	for _, tt := range []struct {
		path string
		tgid string
		want bool
	}{
		{"/proc/thread-self/fd/8", "12", true},
		{"/proc/self/fd/8", "13", true},
		{"/proc/self/fd/8", "12", false},
		{"/proc/thread-self/fd/08", "13", false},
		{"/proc/thread-self/fd/8/proc", "13", false},
	} {
		fd, ok := fuseTargetProcFD(tt.path, []string{tt.tgid}, 13)
		if ok != tt.want || ok && fd != 8 {
			t.Errorf("fuseTargetProcFD(%q, %s, 13) = (%v, %v), want descriptor 8 only for accepted paths", tt.path, tt.tgid, fd, ok)
		}
	}
}

func TestFuseRequesterFilesystemIDs(t *testing.T) {
	mapped, err := mapFuseRequesterIDs([]string{"165536", "165537", "165538", "196608"}, "0 165536 3\n10 196608 30\n")
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"0", "1", "2", "10"} {
		if mapped[i] != want {
			t.Errorf("mapped[%d] = %q, want %q", i, mapped[i], want)
		}
	}
	if _, err := mapFuseRequesterIDs([]string{"165536", "165537", "165538", "196638"}, "0 165536 3\n10 196608 30\n"); err != unix.EOVERFLOW {
		t.Errorf("unmapped fs ID: got %v, want EOVERFLOW", err)
	}
}

func TestFuseTargetKeepsSelectedDescriptor(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	root := t.TempDir()
	dir := filepath.Join(root, "selected")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	data := binary.NativeEndian.AppendUint32(nil, 0)
	data = binary.NativeEndian.AppendUint64(data, 19)
	data = append(data, []byte(dir)...)
	if err := unix.Sendmsg(pair[0], data, unix.UnixRights(fd), nil, 0); err != nil {
		t.Fatal(err)
	}

	// Replacing the authorized pathname cannot redirect the received FD.
	if err := os.Rename(dir, filepath.Join(root, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	target, mountID, err := readFuseMountTarget(pair[1])
	if err != nil {
		t.Fatal(err)
	}
	defer target.file.Close()
	if mountID != 19 || target.path != dir {
		t.Fatalf("received path %q and mount ID %v", target.path, mountID)
	}

	var original, received, replacement unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(target.file.Fd()), &received); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(dir, &replacement); err != nil {
		t.Fatal(err)
	}
	if original.Dev != received.Dev || original.Ino != received.Ino ||
		received.Dev == replacement.Dev && received.Ino == replacement.Ino {
		t.Fatal("transferred FD does not refer to the original object")
	}
}

func TestFuseOverlayMountAncestry(t *testing.T) {
	table, found, err := parseFuseMountTable(`20 19 0:1 / / rw - overlay overlay rw
21 20 0:2 / /nested rw - fuse.fuse-overlayfs fuse-overlayfs rw
22 21 0:3 / /nested/dev rw - tmpfs tmpfs rw
23 21 0:4 / /nested/sysbox rw - fuse sysboxfs rw
24 20 0:5 / /elsewhere rw shared:7 - tmpfs  rw
`)
	if err != nil || !found {
		t.Fatalf("parsed mount table = %v, %v, %v", table, found, err)
	}
	if table[24].source != "" || !table[24].shared {
		t.Fatalf("lost empty mount source or shared flag: %+v", table[24])
	}
	for _, tt := range []struct {
		id   uint64
		want bool
	}{{21, true}, {22, true}, {23, true}, {24, false}, {100, false}} {
		if got := fuseOverlayAncestor(table, tt.id); got != tt.want {
			t.Errorf("mount %d: got %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestFuseBindAtimeOperation(t *testing.T) {
	const bind = unix.MS_BIND | unix.MS_REMOUNT | unix.MS_REC
	for _, tt := range []struct {
		flags uint64
		want  string
	}{
		{bind | unix.MS_NOATIME, "noatime"},
		{bind | unix.MS_RELATIME, "relatime"},
		{bind | unix.MS_STRICTATIME, "strictatime"},
		{bind, ""},
		{bind | unix.MS_RELATIME | unix.MS_NOATIME, ""},
		{bind | unix.MS_RELATIME | unix.MS_RDONLY, ""},
	} {
		if got := fuseBindAtimeOperation(tt.flags); got != tt.want {
			t.Errorf("mount flags %#x: got %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestFuseWorkerReplyDeadline(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	if err := pollFuseWorker(pair[1], 10*time.Millisecond); err != unix.ETIMEDOUT {
		t.Fatalf("silent worker = %v, want ETIMEDOUT", err)
	}
	for _, status := range []unix.Errno{unix.EACCES, 0} {
		data := binary.NativeEndian.AppendUint32(nil, uint32(status))
		if err := unix.Sendmsg(pair[0], data, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		if err := pollFuseWorker(pair[1], time.Second); err != nil {
			t.Fatal(err)
		}
		target, _, err := readFuseMountTarget(pair[1])
		if status == 0 {
			if err != nil || target == nil || target.file != nil {
				t.Fatalf("successful status = (%v, %v)", target, err)
			}
		} else if target != nil || err != status {
			t.Fatalf("failure status = (%v, %v), want %v", target, err, status)
		}
	}
}

func TestFuseWorkerSlots(t *testing.T) {
	limit := fuseWorkerLimit{byContainer: make(map[string]int)}
	for i := 0; i < fuseWorkersPerContainer; i++ {
		if !limit.acquire("first") {
			t.Fatalf("container slot %d unexpectedly refused", i)
		}
	}
	if limit.acquire("first") {
		t.Fatal("container exceeded its worker budget")
	}
	for i := fuseWorkersPerContainer; i < fuseWorkersTotal; i++ {
		if !limit.acquire(strconv.Itoa(i)) {
			t.Fatalf("other container slot %d unexpectedly refused", i)
		}
	}
	if limit.acquire("new") {
		t.Fatal("global worker budget exceeded")
	}
	limit.release("first")
	if !limit.acquire("new") {
		t.Fatal("released global slot did not become available")
	}
	limit.release("new")
	if _, found := limit.byContainer["new"]; found {
		t.Fatal("removed container still has a slot entry")
	}
}
