package main

import (
	"checker/pkg/handler"
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/enowars/enochecker-go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	logger := zap.Must(zap.NewDevelopment())
	defer logger.Sync()
	log := logger.Sugar()

	db := redis.NewClient(&redis.Options{
		Addr:     "phreaking-db:6379",
		Password: string(os.Getenv("REDIS_PASS")),
		DB:       0, // use default DB
	})

	checkerHandler := handler.New(logger, db)
	server := &http.Server{
		Addr:    ":3303",
		Handler: enochecker.NewChecker(log, checkerHandler),
	}
	go func() {
		log.Infof("starting server on port %s...", server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Error(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-ctx.Done()
	stop()

	log.Warnln("stopping server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error(err)
	}
}
