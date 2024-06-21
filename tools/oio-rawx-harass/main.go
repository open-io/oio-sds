// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"errors"
	"openio-sds/tools/oio-rawx-harass/client"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/scenario/ensemble"
	"openio-sds/tools/oio-rawx-harass/scenario/push"
)

var (
	flagQuiet   bool          = false
	flagVerbose bool          = false
	duration    time.Duration = 5 * time.Minute
)

func commandRawxHarass(ctx context.Context) *cobra.Command {
	push := &cobra.Command{
		Use:          "push PATH_TO_FILE",
		Short:        "Push chunks strongly",
		Long:         "",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := push.NewConfig()

			err := cfg.LoadPath(args[0])
			if err != nil {
				log.WithError(err).Error("configuration error")
				return err
			}

			err = scenario.BuildAndRunAndPrint(ctx, cfg.GetTargets(), cfg, duration)
			if err != nil {
				log.WithError(err).Error("run error")
			}
			return err
		},
	}

	script := &cobra.Command{
		Use:          "script PATH_TO_FILE [PATH_TO_FILE...]",
		Short:        "Run multiple concurrent populations",
		Long:         "",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			globalCfg := ensemble.NewConfig()
			globalCfg.Name = "main"

			for _, path := range args {
				localCfg := ensemble.NewConfig()
				localCfg.Name = path

				err := localCfg.LoadPath(path)
				if err == nil {
					globalCfg.Merge(&localCfg)
				} else {
					log.WithError(err).Error("configuration error")
					return err
				}
			}

			log.WithField("files", len(args)).WithField("populations", globalCfg.Count()).Debug("configurations loaded")

			err := scenario.BuildAndRunAndPrint(ctx, globalCfg.GetTargets(), &globalCfg, duration)
			if err != nil {
				log.WithError(err).Error("run error")
			}
			return err
		},
	}

	cmd := &cobra.Command{
		Use:          "oio-rawx-harass [push|script]",
		Short:        "Run multiple concurrent populations",
		Long:         "",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("Missing subcommand")
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if flagQuiet {
				log.SetLevel(log.WarnLevel)
			} else if flagVerbose {
				log.SetLevel(log.DebugLevel)
			}
		},
	}

	cmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", flagVerbose, "Print more verbose output")
	cmd.PersistentFlags().BoolVarP(&flagVerbose, "quiet", "q", flagQuiet, "Print only warnings")
	cmd.PersistentFlags().DurationVarP(&duration, "duration", "d", duration, "General duration of the stress")

	cmd.PersistentFlags().StringVar(&client.Config.Namespace, "ns", client.Config.Namespace, "Set the namespace name")
	cmd.PersistentFlags().StringVar(&client.Config.Prefix, "prefix", client.Config.Prefix, "Restrict the injection to that prefix")
	cmd.PersistentFlags().IntVar(&client.Config.ReuseCnx, "reuse-cnx", client.Config.ReuseCnx, "Reuse the connections or not (1 yes, 0 default, -1 force no)")

	cmd.AddCommand(script)
	cmd.AddCommand(push)
	return cmd
}

func init() {
	//log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle the termination signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	if err := commandRawxHarass(ctx).Execute(); err != nil {
		log.Fatal(err)
	}
}
