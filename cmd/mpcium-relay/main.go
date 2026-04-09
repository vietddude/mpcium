package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fystack/mpcium/internal/relay"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:  "mpcium-relay",
		Usage: "Thin relay runtime for cosigner transport and presence",
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start the relay runtime",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "Path to relay configuration file",
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
						Value: false,
					},
				},
				Action: runRelay,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runRelay(_ context.Context, c *cli.Command) error {
	config.InitViperConfig(c.String("config"))
	viper.SetDefault("presence_events_enabled", true)
	viper.SetDefault("mqtt.listener_id", "relay-mqtt")
	viper.SetDefault("redis.key_prefix", "cosigner")

	environment := viper.GetString("environment")
	logger.Init(environment, c.Bool("debug"))

	relayConfig := config.LoadRelayConfig()
	logger.Info("Loaded relay config", "config", relayConfig.MarshalJSONMask())

	runtime, err := relay.NewRuntime(relayConfig)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			logger.Error("Failed to close relay runtime", closeErr)
		}
	}()

	if err := runtime.Start(); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	return nil
}
