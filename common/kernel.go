package common

import (
	"k8s.io/klog/v2"
	"regexp"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernelVersionRe = regexp.MustCompile(`^(\d+\.\d+)`)
)

func KernelMajorMinor(version string) string {
	return kernelVersionRe.FindString(version)
}

// KernelMonotonicTime gives duration since kernel boot.
func KernelMonotonicTime() time.Duration {
	const clockMonotonic = 1 // It stands for the monotonic clock in Linux kernel.
	var ts syscall.Timespec
	_, _, errCode := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0)
	if errCode != 0 {
		klog.Errorln("Failed to call SYS_CLOCK_GETTIME.")
		return 0
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
}
