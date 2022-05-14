package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

type contextKey string

var contextKeyLogger = contextKey("logger")

func loggerMiddleware(parent zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			logger := parent.With().Str("requestPath", r.URL.Path)

			if requestID, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
				logger = logger.Str("requestID", requestID)
			}

			next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), contextKeyLogger, logger.Logger())))
		})
	}
}

func getRequestLogger(r *http.Request) zerolog.Logger {
	if logger, ok := r.Context().Value(contextKeyLogger).(zerolog.Logger); ok {
		return logger
	}

	return zerolog.Nop()
}
