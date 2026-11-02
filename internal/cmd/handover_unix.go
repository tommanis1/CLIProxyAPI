//go:build !windows

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
)

// handoverDrainTimeout bounds how long a draining core waits for its requests in flight.
const handoverDrainTimeout = 30 * time.Minute

// watchHandoverSignals runs the hot swap: SIGUSR1 prepares (bindings saved, token refresh stopped), SIGUSR2
// drains (stop accepting, finish requests in flight) and then ends the service.
func watchHandoverSignals(ctx context.Context, service *cliproxy.Service, stop context.CancelFunc) {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-signals:
				service.PrepareHandover()
				if sig == syscall.SIGUSR2 {
					service.Drain(handoverDrainTimeout)
					stop()
					return
				}
			}
		}
	}()
}
