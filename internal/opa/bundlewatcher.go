package opa

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
)

type BundleWatcher struct {
	sync.Mutex

	bundleName     string
	bundleRevision string
	statusChan     <-chan Status
	updateChan     chan string
	logger         zerolog.Logger
}

func NewBundleWatcher(bundleName string, statusChan <-chan Status, logger zerolog.Logger) (*BundleWatcher, error) {
	if statusChan == nil {
		return nil, fmt.Errorf("no opa status channel provided")
	}

	return &BundleWatcher{
		bundleName: bundleName,
		statusChan: statusChan,
		updateChan: make(chan string, 1),
		logger:     logger,
	}, nil
}

func (bw *BundleWatcher) Start(ctx context.Context) error {
	defer close(bw.updateChan)

	bw.logger.Debug().Msg("starting")

	if bw.bundleName == "" {
		bw.logger.Warn().
			Str("reason", "no bundle name configured").
			Msg("not watching for bundle updates")
		return nil
	}

	bw.logger.Debug().Str("bundle", bw.bundleName).Msg("watching bundle for changes")

	var (
		status Status
		open   bool
	)

	for {
		select {
		case status, open = <-bw.statusChan:
			if !open {
				bw.logger.Debug().
					Str("reason", "status channel closed").
					Msg("stopping")
				return nil
			}
		case <-ctx.Done():
			bw.logger.Debug().
				Str("reason", ctx.Err().Error()).
				Msg("stopping")
			return ctx.Err()
		}

		for name, bundle := range status.Bundles {
			if bw.updateBundleRevision(name, bundle.ActiveRevision) {
				bw.logger.Info().
					Str("bundle", name).
					Str("revision", bundle.ActiveRevision).
					Msg("bundle update detected")

				select {
				case bw.updateChan <- bundle.ActiveRevision:
				default:
				}
			} else {
				bw.logger.Debug().
					Str("bundle", name).
					Str("revision", bw.bundleRevision).
					Msg("bundle did not change")
			}
		}
	}
}

// UpdateChan returns the channel for bundle updates.
// Items sent over the channel are revisions of the updated bundle.
func (bw *BundleWatcher) UpdateChan() <-chan string {
	return bw.updateChan
}

func (bw *BundleWatcher) updateBundleRevision(name, revision string) bool {
	bw.Lock()
	defer bw.Unlock()

	if bw.bundleName == name && revision != "" && bw.bundleRevision != revision {
		bw.bundleRevision = revision
		return true
	}

	return false
}
