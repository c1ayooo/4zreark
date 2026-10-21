//go:build !linux

package api

import (
	"fmt"
	"os/exec"
)

func detachCmd(cmd *exec.Cmd) {}

func processAlive(pid int) bool { return false }

func terminateProcess(pid int) error {
	return fmt.Errorf("gost 反连自动化只支持 Linux Master")
}

func processMatches(pid int, marker string) bool { return false }
