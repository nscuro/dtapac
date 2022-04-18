package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/model"
)

type findingHandler struct {
	findingsChan chan<- model.Finding
	logger       zerolog.Logger
}

// NewFindingHandler returns a http.Handler that processes NEW_VULNERABILITY notifications.
func NewFindingHandler(findingsChan chan<- model.Finding, logger zerolog.Logger) http.Handler {
	return &findingHandler{
		findingsChan: findingsChan,
		logger:       logger,
	}
}

// ServeHTTP implements the http.Handler interface.
func (fh findingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	requestLogger := getRequestLogger(r, fh.logger)

	n, err := fh.parseNotification(r)
	if err != nil {
		requestLogger.Error().Err(err).Msg("failed to parse notification")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	requestLogger.Debug().
		Str("lvl", n.Level).
		Str("scope", n.Scope).
		Str("group", n.Group).
		Msg("received notification")

	if n.Group != "NEW_VULNERABILITY" {
		requestLogger.Warn().Str("group", n.Group).Msg("notification group is not supported")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	s, ok := n.Subject.(*dtrack.NewVulnerabilitySubject)
	if !ok {
		// The only way this can ever happen is when dtrack-client
		// has a bug in its notification parsing logic.
		requestLogger.Error().
			Str("type", fmt.Sprintf("%T", n.Subject)).
			Msg("notification subject is of unexpected type")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	for i := range s.AffectedProjects {
		finding := model.Finding{
			Component:     s.Component,
			Project:       s.AffectedProjects[i],
			Vulnerability: s.Vulnerability,
		}

		requestLogger.Debug().
			Object("finding", finding).
			Msg("enqueueing finding")

		fh.findingsChan <- finding
	}

	rw.WriteHeader(http.StatusAccepted)
}

func (fh findingHandler) parseNotification(r *http.Request) (*dtrack.Notification, error) {
	defer func() {
		err := r.Body.Close()
		if err != nil {
			requestLogger := getRequestLogger(r, fh.logger)
			requestLogger.Error().Err(err).Msg("failed to close request body")
		}
	}()

	bodyContent, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	return dtrack.ParseNotification(bodyContent)
}

type opaStatus struct {
	Bundles map[string]struct {
		ActiveRevision string `json:"active_revision"`
	} `json:"bundles"`
}

type opaBundleStatusHandler struct {
	bundleName            string
	bundleRevision        string
	bundleMutex           *sync.Mutex
	portfolioAnalysisChan chan<- struct{}
	logger                zerolog.Logger
}

// NewOPABundleStatusHandler returns a http.Handler that processes OPA bundle status updates.
func NewOPABundleStatusHandler(bundle string, portfolioAnalysisChan chan<- struct{}, logger zerolog.Logger) http.Handler {
	return &opaBundleStatusHandler{
		logger:                logger,
		bundleName:            bundle,
		bundleMutex:           &sync.Mutex{},
		portfolioAnalysisChan: portfolioAnalysisChan,
	}
}

// ServeHTTP implements the http.Handler interface.
func (oh *opaBundleStatusHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	requestLogger := getRequestLogger(r, oh.logger)

	status, err := oh.parseStatus(r)
	if err != nil {
		requestLogger.Error().Err(err).Msg("failed to parse status")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	for bundleName, bundle := range status.Bundles {
		if bundleName == oh.bundleName {
			if oh.updateBundleRevision(bundleName, bundle.ActiveRevision) {
				select {
				case oh.portfolioAnalysisChan <- struct{}{}:
					oh.logger.Debug().Msg("portfolio analysis queued")
				default:
					oh.logger.Debug().Msg("there's already a portfolio analysis queued")
				}
			}
		}
	}

	rw.WriteHeader(http.StatusOK)
}

func (oh *opaBundleStatusHandler) updateBundleRevision(name, revision string) bool {
	oh.bundleMutex.Lock()
	defer oh.bundleMutex.Unlock()

	if revision == "" {
		oh.logger.Debug().
			Str("bundle", name).
			Str("reason", "no revision set").
			Msg("not updating bundle status")
		return false
	}

	if revision != oh.bundleRevision {
		oh.logger.Info().
			Str("bundle", name).
			Str("oldRev", oh.bundleRevision).
			Str("newRev", revision).
			Msg("bundle was updated")
		oh.bundleRevision = revision
		return true
	}

	return false
}

func (oh opaBundleStatusHandler) parseStatus(r *http.Request) (opaStatus, error) {
	defer func() {
		err := r.Body.Close()
		if err != nil {
			requestLogger := getRequestLogger(r, oh.logger)
			requestLogger.Error().Err(err).Msg("failed to close request body")
		}
	}()

	var status opaStatus
	err := json.NewDecoder(r.Body).Decode(&status)
	if err != nil {
		return opaStatus{}, fmt.Errorf("failed to decode request body: %w", err)
	}

	return status, nil
}

func getRequestLogger(r *http.Request, parent zerolog.Logger) zerolog.Logger {
	loggerCtx := parent.With().Str("remoteAddr", r.RemoteAddr)

	// RequestID is not available in tests
	if requestID, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
		loggerCtx = loggerCtx.Str("requestID", requestID)
	}

	return loggerCtx.Logger()
}
