package quarks

import (
	"net"
	"time"

	"credhub_setup/pkg/logger"
)

// WaitForHost waits for a given host name to resolve, or there is a failure to
// resolve the host that does not appear to be caused by the Kubernetes service
// not being up yet.
func WaitForHost(hostname string, log logger.Logger) error {
	log.Logf("Waiting for host %s to be available...", hostname)
	for {
		switch _, rawErr := net.LookupHost(hostname); err := rawErr.(type) {
		case nil:
			return nil
		case *net.DNSError:
			if !(err.Temporary() || err.IsNotFound) {
				return err
			}
			time.Sleep(10 * time.Second)
		default:
			return err
		}
	}
	panic("Unreachable code")
}
