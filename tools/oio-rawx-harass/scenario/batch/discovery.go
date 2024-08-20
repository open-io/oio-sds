package batch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"openio-sds/tools/oio-rawx-harass/utils"
)

type discoveredItem struct {
	rx    uint32
	chunk string
	sz    uint64
}

func (pop *population) discoverOneRawx(ctx context.Context, url string, out chan discoveredItem) error {
	pop.Log(ctx).WithField("rawx", url).Debug("discovery starting")
	progress := utils.NewProgress(time.Now(), "discovery/"+url)

	rx, tgt := pop.targets.Find(url)
	for x := range tgt.Iterate(ctx) {
		out <- discoveredItem{rx: rx, chunk: x.Chunk, sz: x.Size}
		progress.TotalPut++
		if progress.TotalPut%64 == 0 {
			progress.PrintPeriodically(ctx, time.Now())
		}
	}
	progress.Print(ctx, time.Now())

	pop.Log(ctx).WithField("rawx", url).WithField("count", progress.TotalPut).Debug("discovery exiting")
	return nil
}

func (pop *population) registerDiscoveredRawx(ctx context.Context, wg *sync.WaitGroup, items chan discoveredItem) {
	pop.Log(ctx).Info("discovery consumer starting")
	progress := utils.NewProgress(time.Now(), "register/"+pop.Id)

	defer wg.Done()
	for x := range items {
		now := time.Now()
		s := pop.generator(now)
		s.Craft(pop.targets, x.rx, x.chunk)
		p := pop.resolveTarget(s.Rawx(pop.targets))
		p.scenarios = append(p.scenarios, s)
		s.globalIndex++
		progress.TotalPut++
		if (progress.TotalPut % 64) == 0 {
			progress.PrintPeriodically(ctx, now)
		}
	}
	progress.Print(ctx, time.Now())
	pop.Log(ctx).Info("discovery consumer exiting")
}

func (pop *population) discoverAllRawx(ctx context.Context) error {
	pop.Log(ctx).Info("discovery orchestrator starting")

	items := make(chan discoveredItem, 64)
	wg := sync.WaitGroup{}
	groupDiscovery, ctx := errgroup.WithContext(ctx)
	groupDiscovery.SetLimit(pop.targets.Count())

	// Consume the discovered items in a centralized goroutine to avoid explicit locking
	wg.Add(1)
	go pop.registerDiscoveredRawx(ctx, &wg, items)

	// Concurrently discover the chunks and produce the items in a channel
	for t := range pop.targets.Urls() {
		t := t
		groupDiscovery.Go(func() error {
			pop.Log(ctx).WithField("rawx", t).Info("discovery producer starting")
			if err := pop.discoverOneRawx(ctx, t, items); err != nil {
				err = fmt.Errorf("discovery failed on target %s: %w", t, err)
				pop.Log(ctx).WithError(err).WithField("rawx", t).Warn("discovery producer failed")
				return err
			} else {
				pop.Log(ctx).WithField("rawx", t).Info("discovery producer exiting")
				return nil
			}
		})
	}

	pop.Log(ctx).Info("discovery orchestrator waiting")

	// Wait for the production to be done then close the channel.
	// The channel closure is the signal that ends the consumer.
	groupDiscovery.Wait()
	close(items)

	// Wait for the consumer to be done
	wg.Wait()

	pop.Log(ctx).Info("discovery orchestrator exiting")
	return nil
}
