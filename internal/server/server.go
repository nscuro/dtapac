package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

type Option func(s *Server) error

func WithHandler(method, pattern string, handler http.Handler) Option {
	return func(s *Server) error {
		s.router.Method(method, pattern, handler)
		return nil
	}
}

func WithLogger(logger zerolog.Logger) Option {
	return func(s *Server) error {
		s.logger = logger
		return nil
	}
}

type Server struct {
	router     chi.Router
	httpServer *http.Server
	logger     zerolog.Logger
}

func New(addr string, opts ...Option) (*Server, error) {
	router := chi.NewRouter()
	router.Use(middleware.RealIP)
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)

	server := Server{
		router: router,
		httpServer: &http.Server{
			Addr:    addr,
			Handler: router,
		},
		logger: zerolog.Nop(),
	}

	for _, opt := range opts {
		err := opt(&server)
		if err != nil {
			return nil, err
		}
	}

	return &server, nil
}

func (s Server) Run() error {
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
