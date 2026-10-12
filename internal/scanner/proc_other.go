//go:build !linux

package scanner

import "os/exec"

func configureProcessGroup(cmd *exec.Cmd) {
	// No-op stub on non-Linux platforms
}
