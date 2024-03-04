package app

import (
	"log/slog"
	"time"

	grpc_ "example.com/m/sso/internal/app/grpc"
	"example.com/m/sso/internal/services/auth"
	"example.com/m/sso/internal/storage/sqlite"
)

type App struct{
	GRPCServer *grpc_.App
}

func NewApp(log *slog.Logger, grpcPort string, storagePath string, token time.Duration) *App{
	storage , err := sqlite.NewDB(storagePath)
	if err != nil {
		panic(err)
	}
	authService := auth.NewAuth(log, storage, token)
	grpcApp := grpc_.NewApp(log, authService, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}