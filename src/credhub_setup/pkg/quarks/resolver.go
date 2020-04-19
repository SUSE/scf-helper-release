package quarks

import (
	"context"
	"net"
	"time"

	"credhub_setup/pkg/logger"
)

// HostLookuper is the function type that is used to look up the host name.
type HostLookuper func (context.Context, string) ([]string, error)

// HostWaiter is a helper to wait for a given host name to resolve.
type HostWaiter struct {
	logger.Logger
	HostLookuper
	time.Duration
}

// WaitForHost waits for a given host name to resolve, or there is a failure to
// resolve the host that does not appear to be caused by the Kubernetes service
// not being up yet.
func (w *HostWaiter) WaitForHost(ctx context.Context, hostname string) error {
	w.Logf("Waiting for host %s to be available...", hostname)
	for {
		_, rawErr := w.HostLookuper(ctx, hostname)
		switch err := rawErr.(type) {
		case nil:
			return nil
		case *net.DNSError:
			if !(err.Temporary() || err.IsNotFound) {
				return err
			}
			time.Sleep(w.Duration)
		default:
			return err
		}
	}
}
