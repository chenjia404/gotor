//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/opd-ai/go-tor/pkg/config"
)

const daemonEnv = "GOTOR_DAEMONIZED"

func daemonizeUnix(cfg *config.Config) error {
	if os.Getenv(daemonEnv) == "1" {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...) // #nosec G204 -- 用自身可执行文件 re-exec，参数即本进程 argv
	cmd.Env = append(os.Environ(), daemonEnv+"=1")
	cmd.Stdin = nil
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304
		if err != nil {
			return fmt.Errorf("daemon log: %w", err)
		}
		cmd.Stdout = f
		cmd.Stderr = f
	} else {
		devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		cmd.Stdout = devnull
		cmd.Stderr = devnull
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
