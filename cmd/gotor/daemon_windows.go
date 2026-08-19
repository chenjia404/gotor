//go:build windows

package main

import "github.com/opd-ai/go-tor/pkg/config"

func daemonizeUnix(cfg *config.Config) error {
	_ = cfg
	return nil
}
