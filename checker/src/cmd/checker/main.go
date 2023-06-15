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
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	db := redis.NewClient(&redis.Options{
		Addr:     "phreaking_checker-phreaking-db-1:6379",
		Password: string(os.Getenv("REDIS_PASS")),
		DB:       0, // use default DB
	})

	checkerHandler := handler.New(log, db)
	server := &http.Server{
		Addr:    ":3303",
		Handler: enochecker.NewChecker(log, checkerHandler),
	}
	go func() {
		log.Printf("starting server on port %s...", server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Error(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-ctx.Done()
	stop()

	log.Println("stopping server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error(err)
	}
}
