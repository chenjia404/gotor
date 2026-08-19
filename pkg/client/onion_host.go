// Package client — 从 torrc OnionServices 启动托管洋葱服务。
package client

import (
	"context"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/onion"
)

// startConfiguredOnionServices 按 Config.OnionServices（HiddenServiceDir/Port）启动托管。
func (c *Client) startConfiguredOnionServices(ctx context.Context) error {
	if c == nil || c.config == nil || len(c.config.OnionServices) == 0 {
		return nil
	}
	byDir := map[string]*onion.ServiceConfig{}
	order := []string{}
	for _, osvc := range c.config.OnionServices {
		if osvc.ServiceDir == "" || osvc.VirtualPort == 0 {
			continue
		}
		sc, ok := byDir[osvc.ServiceDir]
		if !ok {
			sc = &onion.ServiceConfig{
				DataDirectory:  osvc.ServiceDir,
				Ports:          map[int]string{},
				NumIntroPoints: 3,
			}
			byDir[osvc.ServiceDir] = sc
			order = append(order, osvc.ServiceDir)
		}
		sc.Ports[osvc.VirtualPort] = osvc.TargetAddr
	}

	var hsdirs []*onion.HSDirectory
	if c.pathSelector != nil {
		hsdirs = onion.HSDirectoriesFromRelays(c.pathSelector.GetRelays())
	}

	for _, dir := range order {
		sc := byDir[dir]
		svc, err := onion.NewService(sc, c.logger)
		if err != nil {
			return fmt.Errorf("onion service %s: %w", dir, err)
		}
		if err := svc.Start(ctx, hsdirs); err != nil {
			return fmt.Errorf("start onion service %s: %w", dir, err)
		}
		c.logger.Info("onion service started from torrc",
			"dir", dir, "address", svc.GetAddress(), "ports", len(sc.Ports))
	}
	return nil
}
