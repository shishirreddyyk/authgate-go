// Command authgate runs the API gateway.
//
//	AUTHGATE_ADDR      listen address           (default :8080)
//	AUTHGATE_PEPPER    HMAC pepper for key hashing (required in prod)
//	AUTHGATE_REDIS     redis host:port; empty means in-process counters
//	AUTHGATE_LIMIT     requests per window per key (default 60)
//	AUTHGATE_WINDOW    window duration          (default 1m)
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/abuse"
	"github.com/shishirreddyyk/authgate-go/internal/httpapi"
	"github.com/shishirreddyyk/authgate-go/internal/keys"
	"github.com/shishirreddyyk/authgate-go/internal/limiter"
	"github.com/shishirreddyyk/authgate-go/internal/resp"
	"github.com/shishirreddyyk/authgate-go/internal/stats"
)

func main() {
	addr := env("AUTHGATE_ADDR", ":8080")
	pepper := env("AUTHGATE_PEPPER", "dev-only-pepper-do-not-ship")
	redisAddr := env("AUTHGATE_REDIS", "")
	limit := envInt("AUTHGATE_LIMIT", 60)
	window := envDur("AUTHGATE_WINDOW", time.Minute)

	if pepper == "dev-only-pepper-do-not-ship" {
		log.Println("WARNING: using the default pepper. Set AUTHGATE_PEPPER before running this anywhere real.")
	}

	// Counter store. Memory is correct for one replica and wrong for two,
	// so the Redis path is the one that matters in deployment.
	memory := limiter.NewMemory()
	var store limiter.Store = memory
	if redisAddr != "" {
		client := resp.New(redisAddr, 250*time.Millisecond)
		defer client.Close()
		store = limiter.NewRedis(client, "authgate")
		log.Printf("counters: redis at %s", redisAddr)
	} else {
		log.Printf("counters: in-process (single replica only)")
	}

	ks := keys.NewStore([]byte(pepper))
	seedDevKeys(ks)

	tracker := abuse.NewTracker(store, abuse.DefaultConfig())
	recorder := stats.NewRecorder()
	srv := httpapi.New(httpapi.Config{}, ks, limiter.New(store, int64(limit), window), tracker, recorder)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sweep(ctx, memory, tracker, window)

	go func() {
		log.Printf("authgate listening on %s (limit %d per %s per key)", addr, limit, window)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// sweep keeps the in-process maps from growing without bound.
func sweep(ctx context.Context, m *limiter.Memory, t *abuse.Tracker, window time.Duration) {
	interval := window
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.Sweep(window, now)
			t.Sweep(now)
		}
	}
}

// seedDevKeys exists so `docker compose up` gives you something to curl.
// Real deployments provision keys through the admin path.
func seedDevKeys(ks *keys.Store) {
	ks.Add("demo", "demo-secret", "echo:write", "stats:read")
	ks.Add("root", "root-secret", "*")
	log.Println("seeded dev keys: ag_demo_demo-secret (echo, stats), ag_root_root-secret (admin)")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Printf("%s is not a number, using %d", k, def)
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("%s is not a duration, using %s", k, def)
	}
	return def
}
