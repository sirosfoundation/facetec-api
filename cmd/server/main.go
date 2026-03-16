package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/facetec-api/internal/apiv1"
	"github.com/sirosfoundation/facetec-api/internal/config"
	"github.com/sirosfoundation/facetec-api/internal/httpserver"
	"github.com/sirosfoundation/facetec-api/internal/tenant"
)

// Version and Commit are set at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var configFile string
	var printVersion bool
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.BoolVar(&printVersion, "version", false, "Print version and exit")
	flag.Parse()

	if printVersion {
		fmt.Printf("facetec-api version=%s commit=%s\n", Version, Commit)
		return
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "facetec-api: load config: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "facetec-api: invalid config: %v\n", err)
		os.Exit(1)
	}

	log, err := buildLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "facetec-api: init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	log.Info("starting facetec-api",
		zap.String("version", Version),
		zap.String("commit", Commit),
	)

	ctx := context.Background()

	registry, err := tenant.NewRegistry(cfg, log)
	if err != nil {
		log.Fatal("failed to build tenant registry", zap.Error(err))
	}

	// Hot-reload tenant registry on SIGHUP without restarting the process.
	// Validation failures leave the current registry intact.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			log.Info("SIGHUP received — reloading configuration")
			newCfg, err := config.Load(configFile)
			if err != nil {
				log.Warn("hot-reload: failed to load config", zap.Error(err))
				continue
			}
			if err := newCfg.Validate(); err != nil {
				log.Warn("hot-reload: invalid config", zap.Error(err))
				continue
			}
			if err := registry.Reload(newCfg, log); err != nil {
				log.Warn("hot-reload: failed to reload tenant registry", zap.Error(err))
				continue
			}
			log.Info("hot-reload: tenant registry reloaded successfully")
		}
	}()

	apiv1Client, err := apiv1.New(ctx, cfg, registry, log)
	if err != nil {
		log.Fatal("failed to initialise apiv1", zap.Error(err))
	}

	httpSvc := httpserver.New(ctx, cfg, apiv1Client, registry, log)

	// namedService pairs a service with a human-readable name for log messages.
	type namedService struct {
		name string
		svc  service
	}
	// Shutdown order matters: stop accepting HTTP traffic first, then release
	// business-logic resources (session manager + gRPC connection).
	shutdownOrder := []namedService{
		{"http", httpSvc},
		{"apiv1", apiv1Client},
	}

	// Start HTTP server in background.
	go func() {
		if err := httpSvc.Start(ctx); err != nil {
			log.Info("HTTP server stopped", zap.Error(err))
		}
	}()

	log.Info("facetec-api ready", zap.String("addr", cfg.Server.Address()))

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, ns := range shutdownOrder {
		if err := ns.svc.Close(shutdownCtx); err != nil {
			log.Warn("error closing service", zap.String("service", ns.name), zap.Error(err))
		}
	}
	log.Info("shutdown complete")
}

func buildLogger(cfg *config.Config) (*zap.Logger, error) {
	var zapCfg zap.Config
	if cfg.Logging.Production {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
	}
	switch cfg.Logging.Level {
	case "debug":
		zapCfg.Level.SetLevel(zap.DebugLevel)
	case "warn":
		zapCfg.Level.SetLevel(zap.WarnLevel)
	case "error":
		zapCfg.Level.SetLevel(zap.ErrorLevel)
	default:
		zapCfg.Level.SetLevel(zap.InfoLevel)
	}
	return zapCfg.Build()
}
