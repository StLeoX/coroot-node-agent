package common

import (
	"fmt"
)

var (
	kernelVersion Version
)

func SetKernelVersion(version string) error {
	v, err := VersionFromString(version)
	if err != nil || v.Major == 0 {
		return fmt.Errorf("invalid kernel version: %s", version)
	}
	kernelVersion = v
	return nil
}

func GetKernelVersion() Version {
	return kernelVersion
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
