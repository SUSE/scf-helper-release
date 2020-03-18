// credhub_setup is a command used to set up CF application security groups so
// that applications can communicate with the internal CredHub endpoint, as well
// as UAA if appropriate.
package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"credhub_setup/pkg/cc"
	"credhub_setup/pkg/config"
	"credhub_setup/pkg/httpclient"
	"credhub_setup/pkg/logger"
	"credhub_setup/pkg/quarks"
	"credhub_setup/pkg/uaa"
)

type processMode int

const (
	processModeApply  processMode = iota
	processModeRemove processMode = iota
)

func process(ctx context.Context, l logger.Logger, mode processMode) error {
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	config, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}

	tokenURL, err := url.Parse(config.UAATokenURL)
	if err != nil {
		return fmt.Errorf("could not parse token URL: %w", err)
	}

	ccURL, err := url.Parse(config.CCURL)
	if err != nil {
		return fmt.Errorf("could not parse CC URL: %w", err)
	}

	unauthenticatedUAAClient, err := httpclient.MakeHTTPClientWithCA(
		ctx, tokenURL.Hostname(), config.UAACACert)
	if err != nil {
		return err
	}

	unauthenticatedCCClient, err := httpclient.MakeHTTPClientWithCA(
		ctx, ccURL.Hostname(), config.CCCACert)
	if err != nil {
		return err
	}

	if err := quarks.WaitForHost(tokenURL.Hostname(), l); err != nil {
		return err
	}
	if err := quarks.WaitForHost(ccURL.Hostname(), l); err != nil {
		return err
	}

	client, err := uaa.Authenticate(
		ctx,
		unauthenticatedCCClient,
		unauthenticatedUAAClient,
		tokenURL,
		config.OAuthClient,
		config.OAuthSecret,
	)
	if err != nil {
		return err
	}

	builder := &cc.SecurityGroupBuilder{
		Logger:   l,
		Client:   client,
		Endpoint: ccURL,
		Name:     config.Name,
		Address:  config.PodIP,
		Ports:    config.Ports,
	}

	switch mode {
	case processModeApply:
		err = builder.Apply(ctx)
	case processModeRemove:
		err = builder.Remove(ctx)
	default:
		panic(fmt.Sprintf("unexpected processing mode: %v", mode))
	}
	if err != nil {
		return fmt.Errorf("error setting security groups: %w", err)
	}
	return nil
}

func main() {
	ctx := context.Background()
	l := logger.NewAdapter(log.New(os.Stdout, "", log.LstdFlags))
	if len(os.Args) < 2 {
		config.ShowHelp(l)
		return
	}
	switch v := filepath.Base(os.Args[1]); v {
	case "post-start":
		err := process(ctx, l, processModeApply)
		if err != nil {
			l.Logf("Error: %v\n", err)
			os.Exit(1)
		}
	case "drain":
		err := process(ctx, l, processModeRemove)
		if err != nil {
			l.Logf("Error: %v\n", err)
			os.Exit(1)
		}
	case "help", "--help", "-?", "/?":
		config.ShowHelp(l)
	default:
		l.Logf("Unknown command %s\n", v)
		config.ShowHelp(l)
		os.Exit(1)
	}
}
