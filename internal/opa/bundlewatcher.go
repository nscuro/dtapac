package opa

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

type BundleWatcher struct {
	sync.Mutex

	bundleName     string
	bundleRevision string
	statusChan     <-chan Status
	subscriptions  []chan<- struct{}
	logger         zerolog.Logger
}

func NewBundleWatcher(bundleName string, statusChan <-chan Status, logger zerolog.Logger) *BundleWatcher {
	return &BundleWatcher{
		bundleName: bundleName,
		statusChan: statusChan,
		logger:     logger,
	}
}

func (bw *BundleWatcher) Start(ctx context.Context) error {
	defer func() {
		for i := range bw.subscriptions {
			close(bw.subscriptions[i])
		}
	}()

	bw.logger.Info().Msgf("watching bundle %s for changes", bw.bundleName)

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
					Msg("detected bundle update")

				for i := range bw.subscriptions {
					select {
					case bw.subscriptions[i] <- struct{}{}:
					default:
					}
				}
			}
		}
	}
}

// Subscribe adds and returns a new subscription to bundle updates.
func (bw *BundleWatcher) Subscribe() <-chan struct{} {
	bw.Lock()
	defer bw.Unlock()

	subChan := make(chan struct{})
	bw.subscriptions = append(bw.subscriptions, subChan)

	return subChan
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
