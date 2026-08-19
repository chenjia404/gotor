// Package client — 从 torrc OnionServices 启动托管洋葱服务。
package client

import (
	"context"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/onion"
)

// startConfiguredOnionServices 按 Config.OnionServices（HiddenServiceDir/Port）启动托管。
func (c *Client) startConfiguredOnionServices(ctx context.Context) error {
	if c == nil || c.config == nil || len(c.config.OnionServices) == 0 {
		return nil
	}
	if c.pathSelector == nil || c.circuitMgr == nil {
		return fmt.Errorf("circuit manager/path selector required to host onion services")
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

	networkRelays := c.pathSelector.GetRelays()
	hsdirs := onion.HSDirectoriesFromRelays(networkRelays)
	introCandidates := onion.IntroPointCandidatesFromRelays(networkRelays)

	builder := circuit.NewBuilder(c.circuitMgr, c.logger)
	builder.SetCCParams(circuit.CCParamsFromConsensus(c.directory.LastConsensusParams()))
	begindir := onion.NewBegindirFetcher(builder, c.logger)
	begindir.SetRelays(networkRelays)

	for _, dir := range order {
		sc := byDir[dir]
		sc.CircuitBuilder = builder
		sc.PathSelector = c.pathSelector
		sc.Begindir = begindir
		sc.NetworkRelays = networkRelays
		svc, err := onion.NewService(sc, c.logger)
		if err != nil {
			return fmt.Errorf("onion service %s: %w", dir, err)
		}
		pool := introCandidates
		if len(pool) < sc.NumIntroPoints {
			pool = hsdirs
		}
		if err := svc.Start(ctx, pool); err != nil {
			return fmt.Errorf("start onion service %s: %w", dir, err)
		}
		c.logger.Info("onion service started from torrc",
			"dir", dir, "address", svc.GetAddress(), "ports", len(sc.Ports))
	}
	return nil
}
