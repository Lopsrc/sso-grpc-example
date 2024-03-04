package authgrpc

import (
	"context"
	"errors"

	ssov1 "example.com/m/protos/gen/go/sso"
	"example.com/m/sso/internal/domain/models"
	"example.com/m/sso/internal/services/auth"
	utils "example.com/m/sso/internal/grpc/auth/utils"


	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		user *models.UserDTO,
	) (token string, err error)
	RegisterUser(
		ctx context.Context,
		user *models.UserDTO,
	) (string, error)
	Update(
		ctx context.Context,
		user *models.UserUpdateDTO,
	) (token string, err error)
	Delete(
		ctx context.Context,
		user *models.UserDeleteDTO, 
	) (bool, error)
	Recover(
		ctx context.Context,
		user *models.UserRecoverDTO, 
	) (bool, error)
	IsAdmin(
		ctx context.Context,
		userId int64,
	) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (server *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {

	strError, err := utils.ValidateLoginRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	token, err := server.auth.Login(ctx, &models.UserDTO{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppId:    req.GetAppId(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAppId) {
			return nil, status.Error(codes.InvalidArgument, "invalid app id")
        } else	if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		} else if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.InvalidArgument, "user not found")
		}
		return nil, status.Error(codes.Internal, "Internal error")
	}
	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (server *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	
	strError, err := utils.ValidateRegisterRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	token, err := server.auth.RegisterUser(ctx, &models.UserDTO{
		AppId:    req.GetAppId(),
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAppId) {
			return nil, status.Error(codes.InvalidArgument, "invalid app id")
        } else	if errors.Is(err, auth.ErrUserExist) {
			return nil, status.Error(codes.AlreadyExists, "user already exist")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RegisterResponse{
		Token: token,
	}, nil
}

func (server *serverAPI) Update(ctx context.Context, req *ssov1.UpdateRequest) (*ssov1.UpdateResponse, error) {

	strError, err := utils.ValidateUpdateRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	token, err := server.auth.Update(ctx, &models.UserUpdateDTO{
		AppId:    req.GetAppId(),
		Token:    req.GetToken(),
		Password: req.GetPassword(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		} else if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		} else if errors.Is(err, auth.ErrInvalidAppId) {
			return nil, status.Error(codes.InvalidArgument, "invalid app id")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.UpdateResponse{
		Token: token,
	}, nil
}

func (server *serverAPI) Delete(ctx context.Context, req *ssov1.DeleteRequest) (*ssov1.DeleteResponse, error) {

	strError, err := utils.ValidateDeleteRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	isDel, err := server.auth.Delete(ctx, &models.UserDeleteDTO{
		Token: req.GetToken(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		} else if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		} 
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.DeleteResponse{
		IsDelete: isDel,
	}, nil
}

func (server *serverAPI) Recover(ctx context.Context, req *ssov1.RecoverRequest) (*ssov1.RecoverResponse, error) {

	strError, err := utils.ValidateRecoverRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	isRecover, err := server.auth.Recover(ctx, &models.UserRecoverDTO{
		Email: req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}else if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RecoverResponse{
		IsRecover: isRecover,
	}, nil
}

func (server *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {

	strError, err := utils.ValidateIsAdminRequest(req); 
	if err!= nil {
        return nil, status.New(codes.InvalidArgument, strError).Err()
    }

	isAdmin, err := server.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

