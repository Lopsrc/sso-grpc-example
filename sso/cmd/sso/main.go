package main

import (
	// "fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	app "example.com/m/sso/internal/app"
	"example.com/m/sso/internal/config"
)

const(
	pathConfig 			= "sso/config/local.yaml"
	pathConfigDebugging = "../../config/local.yaml"
	envLocal   			= "local"
	envDev     			= "dev"
	envProd    			= "prod"
)
// Run the application.
func main(){
	cfg := config.MustLoadPath(pathConfig)
	
	log := setupLogger(cfg.Env)
	log.Info(
		"start sso", 
		slog.Any("cfg", cfg),
	)

	application := app.NewApp(log, cfg.GRPC.Port, cfg.StoragePath, cfg.TokenTTL)
	
	go func() {
		application.GRPCServer.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	<-stop

	application.GRPCServer.Stop()
	log.Info("gRPC seever stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}

