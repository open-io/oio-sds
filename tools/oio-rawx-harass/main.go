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
	"openio-sds/tools/oio-rawx-harass/scenario/cycle"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/scenario/batch"
	"openio-sds/tools/oio-rawx-harass/scenario/proba"
)

var (
	flagQuiet   bool = false
	flagVerbose bool = false
)

func commandRawxHarass(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "oio-rawx-harass",
		SilenceUsage: false,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Usage()
			return nil
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if flagQuiet {
				log.SetLevel(log.WarnLevel)
			} else if flagVerbose {
				log.SetLevel(log.DebugLevel)
			}
		},
	}

	cmd.PersistentFlags().UintVarP(&client.BufferSize, "size", "s", client.BufferSize, "Set the size of the buffer to be sent (kiB)")
	cmd.PersistentFlags().StringVar(&client.NsName, "ns", "OPENIO", "Set the namespace name")
	cmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", flagVerbose, "Print more verbose output")
	cmd.PersistentFlags().BoolVarP(&flagVerbose, "quiet", "q", flagQuiet, "Print only warnings")

	cmd.AddGroup(&cobra.Group{
		ID:    "Behaviors",
		Title: "Behaviors",
	})
	cmd.AddCommand(CommandStandard(ctx))
	cmd.AddCommand(CommandStandardIA(ctx))
	cmd.AddCommand(CommandGlacierIR(ctx))

	cmd.AddGroup(&cobra.Group{
		ID:    "Other",
		Title: "Other Behaviors",
	})
	cmd.AddCommand(commandPutGetDelete(ctx))
	cmd.AddCommand(commandBatch(ctx))
	return cmd
}

func patchCommandProbabilistic(cmd *cobra.Command, pop *proba.PopulationConfig) {
	cmd.Flags().DurationVarP(&pop.Duration, "duration", "d", 30*time.Second, "Set the duration of the whole test")
	cmd.Flags().IntVar(&pop.MaxWorkers, "concurrency", 64, "Set the number of concurrent coroutines")
	cmd.Flags().Float64Var(&pop.AverageCreationFrequency, "put-freq", pop.AverageCreationFrequency, "Average frequency of the chunk creations")
	cmd.Flags().Float64Var(&pop.AverageGetFrequency, "get-freq", pop.AverageGetFrequency, "Average frequency of each chunk's downloads")
	cmd.Flags().DurationVar(&pop.LifeExpectancy, "life-avg", pop.LifeExpectancy, "Average lifetime of chunks")
	cmd.Flags().DurationVar(&pop.LifeDeviation, "life-dev", pop.LifeDeviation, "Deviation of the lifetime of chunks")
}

func CommandStandard(ctx context.Context) *cobra.Command {
	pop := proba.NewPopulationStandard()
	cmd := &cobra.Command{
		Use:     "standard [RAWX_URL]",
		GroupID: "Behaviors",
		Short:   "Behavior of a user using the STANDARD storage class",
		Long:    "Population of probabilistic behaviors, with defaults depicting the STANDARD storage class",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt := client.RawxTarget{RawxUrl: args}
			client.Prepare()
			return scenario.RunAndPrint(ctx, tgt, pop)
		},
	}
	patchCommandProbabilistic(cmd, pop)
	return cmd
}

func CommandStandardIA(ctx context.Context) *cobra.Command {
	pop := proba.NewPopulationIA()
	cmd := &cobra.Command{
		Use:     "ia [RAWX_URL]",
		GroupID: "Behaviors",
		Short:   "Behavior of a user using the STANDARD-IA storage class",
		Long:    "Population of probabilistic behaviors, with defaults depicting the STANDARD-IA storage class",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt := client.RawxTarget{RawxUrl: args}
			client.Prepare()
			return scenario.RunAndPrint(ctx, tgt, pop)
		},
	}
	patchCommandProbabilistic(cmd, pop)
	return cmd
}

func CommandGlacierIR(ctx context.Context) *cobra.Command {
	pop := proba.NewPopulationGlacier()
	cmd := &cobra.Command{
		Use:     "glacier [RAWX_URL]",
		GroupID: "Behaviors",
		Short:   "Behavior of a user using the GLACIER-IR storage class",
		Long:    "Population of probabilistic behaviors, with defaults depicting the GLACIER-IR storage class",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt := client.RawxTarget{RawxUrl: args}
			client.Prepare()
			return scenario.RunAndPrint(ctx, tgt, pop)
		},
	}
	patchCommandProbabilistic(cmd, pop)
	return cmd
}

func commandPutGetDelete(ctx context.Context) *cobra.Command {
	pop := cycle.PopulationConfig{}
	pop.Duration = 30 * time.Second
	pop.NbWorkers = 8
	pop.NbScenarios = 1024

	cmd := &cobra.Command{
		Use:     "cycle [RAWX_URL]",
		Short:   "Legacy Put/Get/Delete simple cycle",
		Long:    "Scenario cycling through the sequence of Put/Get/Delete of an object",
		Args:    cobra.ExactArgs(1),
		GroupID: "Other",
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt := client.RawxTarget{RawxUrl: args}
			client.Prepare()
			return scenario.RunAndPrint(ctx, tgt, &pop)
		},
	}
	cmd.Flags().DurationVarP(&pop.Duration, "duration", "d", pop.Duration, "Set the duration of the whole test")
	cmd.Flags().UintVar(&pop.NbScenarios, "scenarios", pop.NbScenarios, "Set the number of concurrent scenarios")
	cmd.Flags().UintVar(&pop.NbWorkers, "concurrency", pop.NbWorkers, "Set the number of concurrent coroutines")
	cmd.Flags().BoolVar(&pop.NoGet, "noGet", pop.NoGet, "Disable the read operations")
	cmd.Flags().BoolVar(&pop.NoDel, "noDel", pop.NoDel, "Disable the delete operations")

	return cmd
}

func commandBatch(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "batch [PATH_TO_FILE]",
		Short:   "Run multiple concurrent populations",
		Long:    "",
		Args:    cobra.ExactArgs(1),
		GroupID: "Other",
		RunE: func(cmd *cobra.Command, args []string) error {
			batch := batch.Batch{}
			err := batch.LoadPath(args[0])
			if err == nil {
				err = scenario.RunAndPrint(ctx, batch.Hosts, &batch)
			}
			return err
		},
	}
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
