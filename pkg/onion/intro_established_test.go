package onion

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestHandleIntroCircuitCells_ServiceCancel(t *testing.T) {
	config := &ServiceConfig{AllowPlaceholderIntros: true}
	testLogger := logger.New(slog.LevelWarn, os.Stderr)
	service, err := NewService(config, testLogger)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	mock := newMockCircuit(1)
	est := make(chan error, 1)
	go service.handleIntroCircuitCells(mock, est)
	service.cancel()

	select {
	case err := <-est:
		if err == nil {
			t.Fatal("service cancel should fail the INTRO_ESTABLISHED wait")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for intro handler to observe cancel")
	}
}

func TestHandleIntroCircuitCells_AlreadyCanceled(t *testing.T) {
	config := &ServiceConfig{AllowPlaceholderIntros: true}
	testLogger := logger.New(slog.LevelWarn, os.Stderr)
	service, err := NewService(config, testLogger)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	service.cancel()

	mock := newMockCircuit(1)
	est := make(chan error, 1)
	go service.handleIntroCircuitCells(mock, est)

	select {
	case err := <-est:
		if err == nil {
			t.Fatal("canceled service context should fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for intro handler")
	}
}
