package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nscuro/dtrack-client"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtapac/internal/opa"
)

type Server struct {
	httpServer      *http.Server
	router          chi.Router
	auditResultChan chan any
	opaStatusChan   chan opa.Status
	logger          zerolog.Logger
}

func NewServer(addr string, dtClient *dtrack.Client, auditor audit.Auditor, logger zerolog.Logger) *Server {
	auditChan := make(chan any, 1)
	opaStatusChan := make(chan opa.Status, 1)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(loggerMiddleware(logger))
	router.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.AllowContentType("application/json"))
		r.Post("/dtrack/notification", handleDTNotification(dtClient, auditChan, auditor))
		r.Post("/opa/status", handleOPAStatus(opaStatusChan))
	})
	router.Mount("/metrics", promhttp.Handler())

	return &Server{
		httpServer: &http.Server{
			Addr:    addr,
			Handler: router,
		},
		router:          router,
		auditResultChan: auditChan,
		opaStatusChan:   opaStatusChan,
		logger:          logger,
	}
}

// ServeHTTP implements the http.Handler interface.
func (s Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(rw, r)
}

// Start starts the server and blocks until it is stopped.
// Once stopped, all channels created by the server are closed.
// A server instance can thus not be restarted (although we don't explicitly prevent that right now).
func (s Server) Start() error {
	defer func() {
		close(s.auditResultChan)
		close(s.opaStatusChan)
	}()

	s.logger.Debug().Str("addr", s.httpServer.Addr).Msg("starting")
	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// Stop shuts the server down.
func (s Server) Stop() error {
	s.logger.Debug().Msg("stopping")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// AuditResultChan returns the server's channel for audit results.
func (s Server) AuditResultChan() <-chan any {
	return s.auditResultChan
}

// OPAStatusChan returns the server's channel for OPA status updates.
func (s Server) OPAStatusChan() <-chan opa.Status {
	return s.opaStatusChan
}
