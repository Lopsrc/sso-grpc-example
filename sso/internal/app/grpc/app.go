package grpc_

import (
	"fmt"
	"log/slog"
	"net"

	authgrpc "example.com/m/sso/internal/grpc/auth"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       string
}

func NewApp(log *slog.Logger,authService authgrpc.Auth, port string) *App {
	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, authService)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}
// Run gRPC server.
func (app *App) MustRun() {
	if err := app.Run(); err != nil {
		panic(err)
	}
}

func (app *App) Run() error {

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", app.port))
	if err != nil {
		return fmt.Errorf("Run(): %w", err)
	}

	app.log.Info("grpc server started", slog.Attr{Key: "address: ", Value: slog.StringValue(listener.Addr().String())})

	if err := app.gRPCServer.Serve(listener); err != nil {
		return fmt.Errorf("Run(): %w", err)
	}
	return nil
}

func (app *App) Stop(){
	app.log.Info("stopping gRPC server", slog.String("port", app.port))
	app.gRPCServer.GracefulStop()
}