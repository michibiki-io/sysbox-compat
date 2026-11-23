package seccomp

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRetryMountPropagationInKernel(t *testing.T) {
	tests := []struct {
		name  string
		flags uint64
		err   error
		want  bool
	}{
		{"private", unix.MS_PRIVATE, syscall.ENOENT, true},
		{"recursive private", unix.MS_PRIVATE | unix.MS_REC, syscall.ENOENT, true},
		{"shared", unix.MS_SHARED, syscall.ENOENT, true},
		{"slave", unix.MS_SLAVE, syscall.ENOENT, true},
		{"unbindable", unix.MS_UNBINDABLE, syscall.ENOENT, true},
		{"daemon-side permission error", unix.MS_PRIVATE, syscall.EACCES, true},
		{"invalid path depth", unix.MS_PRIVATE, syscall.ENOTDIR, false},
		{"successful lookup", unix.MS_PRIVATE, nil, false},
		{"bind", unix.MS_BIND, syscall.ENOENT, false},
		{"remount", unix.MS_REMOUNT, syscall.ENOENT, false},
		{"multiple propagation modes", unix.MS_PRIVATE | unix.MS_SHARED, syscall.ENOENT, false},
		{"mixed flags", unix.MS_BIND | unix.MS_PRIVATE, syscall.ENOENT, false},
		{"new mount", 0, syscall.ENOENT, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryMountPropagationInKernel(tt.flags, tt.err); got != tt.want {
				t.Errorf("retryMountPropagationInKernel(%#x, %v) = %t, want %t", tt.flags, tt.err, got, tt.want)
			}
		})
	}
}
