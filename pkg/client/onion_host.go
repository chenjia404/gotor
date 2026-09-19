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
				DataDirectory:      osvc.ServiceDir,
				Ports:              map[int]string{},
				NumIntroPoints:     3,
				PoWDefensesEnabled: osvc.PoWDefensesEnabled,
			}
			byDir[osvc.ServiceDir] = sc
			order = append(order, osvc.ServiceDir)
		}
		sc.Ports[osvc.VirtualPort] = osvc.TargetAddr
		if osvc.PoWDefensesEnabled {
			sc.PoWDefensesEnabled = true
		}
	}

	networkRelays := c.pathSelector.GetRelays()
	introCandidates := onion.IntroPointCandidatesFromRelays(networkRelays)
	if len(introCandidates) == 0 {
		return fmt.Errorf("no Fast+Stable introduction point candidates in consensus")
	}

	builder := circuit.NewBuilder(c.circuitMgr, c.logger)
	builder.SetCCParams(circuit.CCParamsFromConsensus(c.directory.LastConsensusParams()))
	c.attachORTrafficCount(builder)
	begindir := onion.NewBegindirFetcher(builder, c.logger)
	begindir.SetRelays(networkRelays)
	begindir.SetMicrodescLoader(c.directory)
	begindir.SetVanguards(c.vanguards, c.guardManager)
	var srvCur, srvPrev []byte
	if c.directory != nil {
		srvCur, srvPrev = c.directory.SharedRandomValues()
	}
	ring := onion.HSDirRingParamsFromConsensus(nil)
	if c.directory != nil {
		ring = onion.HSDirRingParamsFromConsensus(c.directory.LastConsensusParams())
	}

	for _, dir := range order {
		sc := byDir[dir]
		sc.CircuitBuilder = builder
		sc.PathSelector = c.pathSelector
		sc.Vanguards = c.vanguards
		sc.GuardManager = c.guardManager
		sc.MicrodescLoader = c.directory
		sc.Begindir = begindir
		sc.NetworkRelays = networkRelays
		sc.SharedRandCurrent = srvCur
		sc.SharedRandPrevious = srvPrev
		sc.HSDirRing = ring
		svc, err := onion.NewService(sc, c.logger)
		if err != nil {
			return fmt.Errorf("onion service %s: %w", dir, err)
		}
		if err := svc.Start(ctx, introCandidates); err != nil {
			c.hostedMu.Lock()
			started := append([]*onion.Service(nil), c.hostedServices...)
			c.hostedMu.Unlock()
			for _, prev := range started {
				_ = prev.Stop()
			}
			return fmt.Errorf("start onion service %s: %w", dir, err)
		}
		c.hostedMu.Lock()
		c.hostedServices = append(c.hostedServices, svc)
		c.hostedMu.Unlock()
		c.logger.Info("onion service started from torrc",
			"dir", dir, "address", svc.GetAddress(), "ports", len(sc.Ports))
	}
	return nil
}
