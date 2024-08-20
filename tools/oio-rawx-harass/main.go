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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/scenario/ensemble"
	"openio-sds/tools/oio-rawx-harass/scenario/push"
	"openio-sds/tools/oio-rawx-harass/utils"
)

var (
	flagJson    bool          = false
	flagQuiet   bool          = false
	flagVerbose bool          = false
	dataDir     string        = getEnv2("HARASS_DATA_DIR", ".")
	duration    time.Duration = 0
)

func getEnv2(k string, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	} else {
		return v
	}
}

func commandLoad(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:          "load URL PATH_TO_FILE",
		Short:        "Read the manifest of volume from a test file",
		Long:         "",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			path := args[1]

			tgt, err := config.NewTargets(ctx, dataDir, []string{url})
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("url", url).Error("state open error")
				return err
			}
			defer tgt.Close()

			rawx := tgt.Get(0)

			progress := utils.NewProgress(time.Now(), "load/"+url+"/"+path)

			f, err := os.Open(path)
			defer f.Close()
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", path).Error("listing open error")
				return err
			}
			for s := bufio.NewScanner(f); s.Scan() && ctx.Err() == nil; {
				chunkID := strings.Trim(s.Text(), " \t\r\n")
				if chunkID == "" || strings.HasPrefix(chunkID, "#") {
					continue
				}
				if err = rawx.Save(chunkID); err != nil {
					err = fmt.Errorf("Chunk insertion error at line=%d chunk=%s: %w", progress.TotalPut, chunkID, err)
					break
				} else {
					progress.TotalPut++
					//utils.Log(ctx).WithField("url", url).WithField("chunk", chunkID).Debug("inserted")
					if (progress.TotalPut % 64) == 0 {
						progress.PrintPeriodically(ctx, time.Now())
					}
				}
			}
			progress.Print(ctx, time.Now())

			if err == nil {
				err = ctx.Err()
			}

			if err != nil {
				utils.Log(ctx).WithError(err).WithField("count", progress.TotalPut).WithField("url", url).WithField("path", path).Error("manifest loading error")
				return err
			} else {
				utils.Log(ctx).WithField("count", progress.TotalPut).WithField("url", url).WithField("path", path).WithError(err).Info("manifest loading done")
				return nil
			}
		},
	}
}

func commandScan(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:          "scan URL PATH_TO_VOL",
		Short:        "Fill the state of the volume",
		Long:         "",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			vol := args[1]

			tgt, err := config.NewTargets(ctx, dataDir, []string{url})
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", url).Error("state open error")
				return err
			}
			defer tgt.Close()

			rawx := tgt.Get(0)

			progress := utils.NewProgress(time.Now(), "scan/"+url+"/"+vol)
			err = filepath.WalkDir(vol, func(path string, info os.DirEntry, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !info.IsDir() && !strings.HasSuffix(path, ".pending") {
					if e := rawx.Save(filepath.Base(path)); e != nil {
						return e
					} else {
						progress.TotalPut++
						if (progress.TotalPut % 1024) == 0 {
							progress.PrintPeriodically(ctx, time.Now())
						}
					}
				}
				return nil
			})

			progress.Print(ctx, time.Now())

			if err != nil {
				utils.Log(ctx).WithError(err).WithField("url", url).WithField("path", vol).WithError(err).Error("volume scan error")
				return err
			} else {
				return nil
			}
		},
	}
}

func commandWalk(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:          "walk PATH_TO_VOL",
		Short:        "Like find but slower",
		Long:         "",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			vol := args[0]

			progress := utils.NewProgress(time.Now(), "walk/"+vol)
			err := filepath.WalkDir(vol, func(path string, info os.DirEntry, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !info.IsDir() && !strings.HasSuffix(path, ".pending") {
					fmt.Println(filepath.Base(path))
					progress.TotalPut++
					if (progress.TotalPut % 1024) == 0 {
						progress.PrintPeriodically(ctx, time.Now())
					}
				}
				return nil
			})

			progress.Print(ctx, time.Now())

			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", vol).WithError(err).Error("volume walk error")
				return err
			} else {
				return nil
			}
		},
	}
}

func commandPush(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:          "push SIZES TARGETS LOAD",
		Short:        "Push chunks as fast as possible",
		Long:         "",
		Args:         cobra.ExactArgs(3),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			sz, err := config.LoadSizes(ctx, args[0])
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", args[0]).Error("sizes loading error")
				return err
			}

			tgt, err := config.LoadTargetsPath(ctx, dataDir, args[1])
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", args[1]).Error("targets loading error")
				return err
			} else {
				defer tgt.Close()
			}

			var r *scenario.Runner

			cfg := push.NewConfig()
			if err = cfg.LoadPath(args[2]); err != nil {
				utils.Log(ctx).WithError(err).WithField("path", args[2]).Error("configuration error")
				return err
			} else if r, err = scenario.NewRunner(ctx, cfg, tgt, sz); err != nil {
				utils.Log(ctx).WithError(err).WithField("path", args[2]).Error("instantiation error")
				return err
			} else if err = r.RunAndPrint(ctx, duration); err != nil {
				utils.Log(ctx).WithError(err).Error("run error")
				return err
			} else {
				return nil
			}
		},
	}
}

func commandStress(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:          "stress SIZES TARGETS SCRIPT [SCRIPT...]",
		Short:        "Run multiple concurrent populations",
		Long:         "",
		Args:         cobra.MinimumNArgs(3),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			pathSizes := args[0]
			pathTargets := args[1]

			sz, err := config.LoadSizes(ctx, pathSizes)
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", pathSizes).Error("sizes loading error")
				return err
			} else {
				utils.Log(ctx).WithField("targets", *sz).WithField("path", pathSizes).Info("sizes loaded")
			}

			tgt, err := config.LoadTargetsPath(ctx, dataDir, pathTargets)
			if err != nil {
				utils.Log(ctx).WithError(err).WithField("path", pathTargets).Error("targets loading error")
				return err
			} else {
				utils.Log(ctx).WithField("targets", *tgt).WithField("path", pathTargets).Info("targets loaded")
				defer tgt.Close()
			}

			globalCfg := ensemble.NamedConfig("main")

			for _, path := range args[2:] {
				localCfg := ensemble.NamedConfig(path)
				if err = localCfg.LoadPath(ctx, path); err != nil {
					utils.Log(ctx).WithError(err).Error("configuration error")
					return err
				}
				globalCfg.Merge(&localCfg)
			}

			utils.Log(ctx).WithField("files", len(args[2:])).WithField("populations", globalCfg.Count()).Debug("configurations loaded")

			var r *scenario.Runner
			if r, err = scenario.NewRunner(ctx, &globalCfg, tgt, sz); err != nil {
				utils.Log(ctx).WithError(err).WithField("targets", *tgt).WithField("sizes", *sz).Error("instantiation error")
				return err
			} else if err = r.RunAndPrint(ctx, duration); err != nil {
				utils.Log(ctx).WithError(err).WithField("targets", *tgt).WithField("sizes", *sz).Error("run error")
				return err
			} else {
				return nil
			}
		},
	}
}

func commandMain(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "oio-rawx-harass [push|run]",
		Short:        "Run multiple concurrent populations",
		Long:         "",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("missing subcommand")
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if flagQuiet {
				log.SetLevel(log.WarnLevel)
			} else if flagVerbose {
				log.SetLevel(log.DebugLevel)
			}
			if flagJson {
				log.SetFormatter(&log.JSONFormatter{
					TimestampFormat:   "2006-01-02 15:04:05",
					PrettyPrint:       false,
					DisableHTMLEscape: true,
					DisableTimestamp:  false,
				})
				log.SetOutput(os.Stdout)
			}
		},
	}

	cmd.PersistentFlags().BoolVarP(&flagJson, "json", "j", flagJson, "log in JSON")
	cmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", flagVerbose, "Print more verbose output")
	cmd.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", flagQuiet, "Print only warnings")
	cmd.PersistentFlags().DurationVarP(&duration, "duration", "d", duration, "General duration of the stress phase (no impact on warmup and cleanup phases)")
	cmd.PersistentFlags().StringVarP(&dataDir, "data", "D", dataDir, "General duration of the stress")

	cmd.PersistentFlags().BoolVar(&client.DisablePersist, "disable-persist", client.DisablePersist, "Disable the persistence of states alterations")
	cmd.PersistentFlags().StringVar(&client.Config.Namespace, "ns", client.Config.Namespace, "Set the namespace name")
	cmd.PersistentFlags().StringVar(&client.Config.Prefix, "prefix", client.Config.Prefix, "Restrict the injection to that prefix")
	cmd.PersistentFlags().IntVar(&client.Config.ReuseCnx, "reuse-cnx", client.Config.ReuseCnx, "Reuse the connections or not (1 yes, 0 default, -1 force no)")

	cmd.AddCommand(commandStress(ctx))
	cmd.AddCommand(commandPush(ctx))
	cmd.AddCommand(commandScan(ctx))
	cmd.AddCommand(commandLoad(ctx))
	cmd.AddCommand(commandWalk(ctx))
	return cmd
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableQuote:           true,
		DisableLevelTruncation: false,
		DisableSorting:         false,
		DisableColors:          true,
		DisableTimestamp:       false,
		PadLevelText:           false,
		TimestampFormat:        "2006-01-02 15:04:05",
		QuoteEmptyFields:       false,
		ForceColors:            false,
		ForceQuote:             false,
	})
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

	if err := commandMain(ctx).Execute(); err != nil {
		utils.Log(ctx).WithError(err).Fatal("Main command execution failed")
	}
}
