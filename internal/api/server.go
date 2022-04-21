package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/nscuro/dtapac/internal/opa"
)

type Server struct {
	httpServer *http.Server
	router     chi.Router
	logger     zerolog.Logger
}

func NewServer(addr string, auditChan chan<- any, opaStatusChan chan<- opa.Status, logger zerolog.Logger) *Server {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(loggerMiddleware(logger))
	router.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.AllowContentType("application/json"))
		r.Post("/dtrack/notification", handleNotification(auditChan))
		r.Post("/opa/status", handleOPAStatus(opaStatusChan))
	})

	return &Server{
		httpServer: &http.Server{
			Addr:    addr,
			Handler: router,
		},
		router: router,
		logger: logger,
	}
}

// ServeHTTP implements the http.Handler interface.
func (s Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(rw, r)
}

func (s Server) Start() error {
	s.logger.Debug().Str("addr", s.httpServer.Addr).Msg("starting")
	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (s Server) Stop(ctx context.Context) error {
	s.logger.Debug().Msg("stopping")
	return s.httpServer.Shutdown(ctx)
}
