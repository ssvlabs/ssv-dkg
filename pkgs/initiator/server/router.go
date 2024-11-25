package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"go.uber.org/zap"
)

// request limits
const (
	generalLimit = 5000
	timePeriod   = time.Minute
)

// RegisterRoutes creates routes at operator to process messages incoming from initiator
func RegisterRoutes(s *Server) {
	s.Router.Use(rateLimit(s.Logger, generalLimit))
	addRoute(s.Router, "POST", "/init", s.initHandler, rateLimit(s.Logger, generalLimit))
	// addRoute(s.Router, "GET", "/health_check", s.healthHandler, rateLimit(s.Logger, generalLimit))
	// addRoute(s.Router, "POST", "/resign", s.signedResignHandler, rateLimit(s.Logger, generalLimit))
	// addRoute(s.Router, "POST", "/reshare", s.signedReshareHandler, rateLimit(s.Logger, generalLimit))
}

// Add route with optional middleware
func addRoute(router chi.Router, method, path string, handler http.HandlerFunc, middleware ...func(http.Handler) http.Handler) {
	if len(middleware) > 0 {
		router.With(middleware...).MethodFunc(method, path, handler)
	} else {
		router.MethodFunc(method, path, handler)
	}
}

func rateLimit(logger *zap.Logger, limit int) func(http.Handler) http.Handler {
	return httprate.Limit(
		limit,
		timePeriod,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("rate limit exceeded",
				zap.String("ip", r.RemoteAddr),
				zap.String("path", r.URL.Path))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, err := w.Write([]byte(ErrTooManyRouteRequests))
			if err != nil {
				logger.Error("error writing rate limit response", zap.Error(err))
			}
		}),
	)
}
