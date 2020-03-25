package quarks_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"credhub_setup/pkg/quarks"
)

func TestWaitForHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const wantedHostname = "somewhere.invalid"

	t.Run("immediate success", func(t *testing.T) {
		lookuper := func(ctx context.Context, hostname string) ([]string, error) {
			assert.Equal(t, wantedHostname, hostname, "unexpected host name")
			return []string{}, nil
		}
		waiter := quarks.HostWaiter{
			Logger:       t,
			HostLookuper: lookuper,
			Duration:     0,
		}
		err := waiter.WaitForHost(ctx, wantedHostname)
		assert.NoError(t, err, "unexpected error looking up host")
	})

	t.Run("temporary failure", func(t *testing.T) {
		counter := 0
		lookuper := func(ctx context.Context, hostname string) ([]string, error) {
			assert.Equal(t, wantedHostname, hostname, "unexpected host name")
			if counter < 10 {
				counter += 1
				return nil, &net.DNSError{IsTemporary: true}
			}
			return []string{}, nil
		}
		waiter := quarks.HostWaiter{
			Logger:       t,
			HostLookuper: lookuper,
			Duration:     0,
		}
		err := waiter.WaitForHost(ctx, wantedHostname)
		assert.NoError(t, err, "unexpected error looking up host")
	})

	t.Run("not found", func(t *testing.T) {
		counter := 0
		lookuper := func(ctx context.Context, hostname string) ([]string, error) {
			assert.Equal(t, wantedHostname, hostname, "unexpected host name")
			if counter < 10 {
				counter += 1
				return nil, &net.DNSError{IsNotFound: true}
			}
			return []string{}, nil
		}
		waiter := quarks.HostWaiter{
			Logger:       t,
			HostLookuper: lookuper,
			Duration:     0,
		}
		err := waiter.WaitForHost(ctx, wantedHostname)
		assert.NoError(t, err, "unexpected error looking up host")
	})

	t.Run("other DNS error", func(t *testing.T) {
		lookuper := func(ctx context.Context, hostname string) ([]string, error) {
			assert.Equal(t, wantedHostname, hostname, "unexpected host name")
			return nil, &net.DNSError{}
		}
		waiter := quarks.HostWaiter{
			Logger:       t,
			HostLookuper: lookuper,
			Duration:     0,
		}
		err := waiter.WaitForHost(ctx, wantedHostname)
		assert.Error(t, err, "unexpected DNS error should propagate")
	})

	t.Run("other error", func(t *testing.T) {
		lookuper := func(ctx context.Context, hostname string) ([]string, error) {
			assert.Equal(t, wantedHostname, hostname, "unexpected host name")
			return nil, fmt.Errorf("unrelated error")
		}
		waiter := quarks.HostWaiter{
			Logger:       t,
			HostLookuper: lookuper,
			Duration:     0,
		}
		err := waiter.WaitForHost(ctx, wantedHostname)
		assert.Error(t, err, "unexpected error should propagate")
	})
}
