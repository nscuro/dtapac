package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/nscuro/dtrack-client"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/nscuro/dtapac/internal/api"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

func main() {
	fs := flag.NewFlagSet("dtapac", flag.ContinueOnError)
	fs.String("config", "", "Path to config file")

	var opts options
	fs.StringVar(&opts.Host, "host", "0.0.0.0", "Host to listen on")
	fs.UintVar(&opts.Port, "port", 8080, "Port to listen on")
	fs.StringVar(&opts.DTrackURL, "dtrack-url", "", "Dependency-Track API server URL")
	fs.StringVar(&opts.DTrackAPIKey, "dtrack-apikey", "", "Dependency-Track API key")
	fs.StringVar(&opts.OPAURL, "opa-url", "", "Open Policy Agent URL")
	fs.StringVar(&opts.WatchBundle, "watch-bundle", "", "OPA bundle to watch")
	fs.StringVar(&opts.FindingPolicyPath, "finding-policy-path", "", "Policy path for finding analysis")
	fs.StringVar(&opts.ViolationPolicyPath, "violation-policy-path", "", "Policy path for violation analysis")
	fs.UintVar(&opts.AuditWorkers, "audit-workers", 2, "Number of audit workers")

	cmd := ffcli.Command{
		Name: "dtapac",
		Options: []ff.Option{
			ff.WithEnvVarNoPrefix(),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithAllowMissingConfigFile(true),
		},
		FlagSet: fs,
		Exec: func(ctx context.Context, _ []string) error {
			return exec(ctx, opts)
		},
	}

	err := cmd.ParseAndRun(context.Background(), os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	Host                string
	Port                uint
	DTrackURL           string
	DTrackAPIKey        string
	OPAURL              string
	WatchBundle         string
	FindingPolicyPath   string
	ViolationPolicyPath string
	AuditWorkers        uint
}

func exec(ctx context.Context, opts options) error {
	logger := log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr,
	})

	_, err := dtrack.NewClient(opts.DTrackURL, dtrack.WithAPIKey(opts.DTrackAPIKey))
	if err != nil {
		return fmt.Errorf("failed to setup dtrack client: %w", err)
	}

	opaClient, err := opa.NewClient(opts.OPAURL)
	if err != nil {
		return fmt.Errorf("failed to setup opa client: %w", err)
	}

	apiServerAddr := net.JoinHostPort(opts.Host, strconv.FormatUint(uint64(opts.Port), 10))
	apiServer := api.NewServer(apiServerAddr, serviceLogger("apiServer", logger))

	auditor := audit.NewAuditor(opaClient, apiServer.AuditChan(),
		audit.WithFindingPolicyPath(opts.FindingPolicyPath),
		audit.WithViolationPolicyPath(opts.ViolationPolicyPath),
		audit.WithWorkers(opts.AuditWorkers),
		audit.WithLogger(serviceLogger("auditor", logger)))

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(apiServer.Start)
	eg.Go(func() error {
		return auditor.Start(egCtx)
	})
	eg.Go(func() error {
		for input := range auditor.OutputChan() {
			logger.Info().Interface("input", input).Msg("got audit result")
		}

		return nil
	})

	if opts.WatchBundle != "" {
		bundleWatcher := opa.NewBundleWatcher(opts.WatchBundle, apiServer.OPAStatusChan(), serviceLogger("bundleWatcher", logger))

		eg.Go(func() error {
			return bundleWatcher.Start(egCtx)
		})
	}

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	select {
	case <-termChan:
		logger.Debug().Str("reason", "shutdown requested").Msg("shutting down")
	case <-egCtx.Done():
		logger.Debug().Str("reason", egCtx.Err().Error()).Msg("shutting down")
	}

	err = apiServer.Stop()
	if err != nil {
		logger.Error().Err(err).Msg("failed to shutdown api server")
	}

	return eg.Wait()
}

func serviceLogger(name string, parent zerolog.Logger) zerolog.Logger {
	return parent.With().Str("svc", name).Logger()
}
