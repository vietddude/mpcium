package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	rbconfig "github.com/fystack/mpcium/internal/relaybridge/config"
	rbruntime "github.com/fystack/mpcium/internal/relaybridge/runtime"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:  "mpcium-sdk-node",
		Usage: "Run isolated mpcium-sdk keygen/sign flow over relay subjects",
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start the isolated SDK flow runtime",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "config",
						Aliases:  []string{"c"},
						Usage:    "Path to SDK flow configuration file",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
					},
				},
				Action: run,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(_ context.Context, c *cli.Command) error {
	viper.SetConfigFile(c.String("config"))
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	var cfg rbconfig.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger.Init(cfg.Environment, c.Bool("debug"))

	runtime, err := rbruntime.New(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return runtime.Run(ctx)
}
