package suite

import (
	"context"
	"net"
	"testing"

	ssov1 "example.com/m/protos/gen/go/sso"
	"example.com/m/sso/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)
const (
	grpsHost = "localhost"
)
type Suite struct{
	*testing.T
	Cfg *config.Config
	AuthClient ssov1.AuthClient
}

func NewSuit(test *testing.T) (context.Context, *Suite) {
	test.Helper()
	test.Parallel()

	cfg := config.MustLoadPath("../config/local_tests.yaml")

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	test.Cleanup(func(){
		test.Helper()
		cancelCtx()
	})

	cc, err := grpc.DialContext(context.Background(), grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		test.Fatalf("grpc server connection failed: %v", err)
	}

	return ctx, &Suite{
		T: test,
		Cfg: cfg,
		AuthClient: ssov1.NewAuthClient(cc),

	}
}

func grpcAddress(cfg *config.Config) string{
	return net.JoinHostPort(grpsHost, cfg.GRPC.Port)
}