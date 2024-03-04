package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"example.com/m/sso/internal/domain/models"
	"example.com/m/sso/internal/lib/jwt"
	"example.com/m/sso/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserExist          = errors.New("user already exist")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenNotFound      = errors.New("token not found")
)

const (
	opRegister = "Auth. Register"
	opLogin    = "Auth. Login"
	opUpdate   = "Auth. Update"
	opDelete   = "Auth. Delete"
	opRecover  = "Auth. Recover"
	opIsAdmin  = "Auth. IsAdmin"
)

type Auth struct {
	log           *slog.Logger
	authInterface AuthInterface
	token         time.Duration
}

type AuthInterface interface {
	AddUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (models.TokenCreateDTO, error)
	CreateToken(
		ctx context.Context,
		user models.TokenCreateDTO,
		token string,
	) error
	LoginUser(
		ctx context.Context,
		userId int64,
		token string,
	) error
	UpdateUser(
		ctx context.Context,
		userId int64,
		passhash []byte,
		token string,
	) error
	DeleteUser(
		ctx context.Context,
		userId int64,
	) error
	RecoverUser(
		ctx context.Context,
		userId int64,
	) error
	IsAdmin(
		ctx context.Context,
		userId int64,
	) (bool, error)
	GetUser(
		ctx context.Context,
		email string,
	) (models.User, error)
	GetUserById(
		ctx context.Context,
		userId int64,
	) (models.User, error)
	GetApp(
		ctx context.Context,
		appid int32,
	) (models.App, error)
	GetUserIdbyToken(
		ctx context.Context,
		token string,
	) (int64, error)
}

func NewAuth(
	log *slog.Logger,
	authInterface AuthInterface,
	token time.Duration,
) *Auth {

	return &Auth{
		log:           log,
		authInterface: authInterface,
		token:         token,
	}
}

func (ath *Auth) RegisterUser(
	ctx context.Context,
	user *models.UserDTO,
) (string, error) {
	ath.log.Info("Auth. Register new user.")

	passHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		ath.log.Error("failed to generate hash")
		return "", fmt.Errorf("%s: %w", opRegister, err)
	}
	userUp, err := ath.authInterface.AddUser(ctx, user.Email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			ath.log.Warn("user already exist")
			return "", fmt.Errorf("%s: %w", opRegister, ErrUserExist)
		}
		ath.log.Error("failed to add user %w", err)
		return "", fmt.Errorf("%s: %w", opRegister, err)
	}

	token, err := ath.GenerateToken(ctx, &models.User{
		Id:       userUp.Id,
		Email:    user.Email,
		Passhash: passHash,
	}, user.AppId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			ath.log.Warn("app not found")
			return "", fmt.Errorf("%s: %w", opIsAdmin, ErrInvalidAppId)
		}
		ath.log.Info("failed to generate token")
		return "", fmt.Errorf("%s: %w", opLogin, err)
	}

	if err = ath.authInterface.CreateToken(ctx, userUp, token); err != nil {
		ath.log.Info("failed to create token")
		return "", fmt.Errorf("%s: %w", opLogin, err)
	}

	return token, nil
}

func (ath *Auth) Login(
	ctx context.Context,
	user *models.UserDTO,
) (string, error) {
	ath.log.Info("Auth. Login.")

	usr, err := ath.authInterface.GetUser(ctx, user.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ath.log.Warn("user not found")
			return "", fmt.Errorf("%s: %w", opRecover, ErrUserNotFound)
		}
		ath.log.Error("failed to get user %w", err)
		return "", fmt.Errorf("%s: %w", opRecover, err)
	}
	if usr.Del {
		ath.log.Warn("user is deleted")
		return "", fmt.Errorf("%s: %w", opRecover, ErrInvalidCredentials)
	}

	if err := bcrypt.CompareHashAndPassword(usr.Passhash, []byte(user.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			ath.log.Warn("invalid credentials")
			return "", fmt.Errorf("%s: %w", opRecover, ErrInvalidCredentials)
		}
		ath.log.Info("failed to generate passHash")
		return "", fmt.Errorf("%s: %w", opLogin, err)
	}

	token, err := ath.GenerateToken(ctx, &models.User{
		Id:       usr.Id,
		Email:    usr.Email,
		Passhash: usr.Passhash,
	}, user.AppId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			ath.log.Warn("app not found")
			return "", fmt.Errorf("%s: %w", opLogin, ErrInvalidAppId)
		}
		ath.log.Info("failed to generate token")
		return "", fmt.Errorf("%s: %w", opLogin, err)
	}

	if err = ath.authInterface.LoginUser(ctx, usr.Id, token); err != nil {
		ath.log.Info("failed to create token")
		return "", fmt.Errorf("%s: %w", opLogin, err)
	}

	return token, nil
}

func (ath *Auth) Update(
	ctx context.Context,
	userUpdate *models.UserUpdateDTO,
) (string, error) {
	ath.log.Info("Auth. Update user.")

	if err := jwt.VerifyToken(userUpdate.Token); err != nil {
		if errors.Is(err, jwt.ErrInvalidVerifyToken) {
			ath.log.Warn("invalid token")
			return "", fmt.Errorf("%s: %w", opUpdate, ErrInvalidToken)
		}
		ath.log.Error("failed to get token id: %w", err)
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}

	userId, err := ath.authInterface.GetUserIdbyToken(ctx, userUpdate.Token)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			ath.log.Warn("invalid credentials. token not found")
			return "", fmt.Errorf("%s: %w", opDelete, ErrInvalidCredentials)
		}
		ath.log.Error("failed to get token id: %w", err)
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}

	user, err := ath.authInterface.GetUserById(ctx, userId)
	if err != nil {
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(userUpdate.Password), bcrypt.DefaultCost)
	if err != nil {
		ath.log.Error("failed to generate hash")
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}

	token, err := ath.GenerateToken(ctx, &models.User{
		Id:       user.Id,
		Email:    user.Email,
		Passhash: passHash,
	}, userUpdate.AppId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			ath.log.Warn("app not found")
			return "", fmt.Errorf("%s: %w", opUpdate, ErrInvalidAppId)
		}
		ath.log.Info("failed to generate token")
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}

	if err = ath.authInterface.UpdateUser(ctx, userId, passHash, token); err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			ath.log.Warn("user already exist")
			return "", fmt.Errorf("%s: %w", opUpdate, ErrUserExist)
		}
		ath.log.Error("failed to update user %w", err)
		return "", fmt.Errorf("%s: %w", opUpdate, err)
	}
	return token, nil
}

func (ath *Auth) Delete(
	ctx context.Context,
	user *models.UserDeleteDTO,
) (bool, error) {
	ath.log.Info("Auth. Delete user.")

	if err := jwt.VerifyToken(user.Token); err != nil {
		if errors.Is(err, jwt.ErrInvalidVerifyToken) { 
			ath.log.Warn("invalid token")
			return false, fmt.Errorf("%s: %w", opDelete, ErrInvalidToken)
		}
		ath.log.Error("failed to get token id: %w", err)
		return false, fmt.Errorf("%s: %w", opDelete, err)
	}
	userId, err := ath.authInterface.GetUserIdbyToken(ctx, user.Token)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			ath.log.Warn("invalid credentials. token not found")
			return false, fmt.Errorf("%s: %w", opDelete, ErrInvalidCredentials)
		}
		ath.log.Error("failed to get token id")
		return false, fmt.Errorf("%s: %w", opUpdate, err)
	}

	if err := ath.authInterface.DeleteUser(ctx, userId); err != nil {
		ath.log.Error("failed to delete user %w", err)
		return false, fmt.Errorf("%s: %w", opDelete, err)
	}

	return true, nil
}

func (ath *Auth) Recover(
	ctx context.Context,
	user *models.UserRecoverDTO,
) (bool, error) {
	ath.log.Info("Auth. Recover user.")

	usr, err := ath.authInterface.GetUser(ctx, user.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ath.log.Warn("user not found")
			return false, fmt.Errorf("%s: %w", opRecover, ErrUserNotFound)
		}
		ath.log.Error("failed to get user %w", err)
		return false, fmt.Errorf("%s: %w", opRecover, err)
	}

	if err := bcrypt.CompareHashAndPassword(usr.Passhash, []byte(user.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			ath.log.Warn("invalid credentials")
			return false, fmt.Errorf("%s: %w", opRecover, ErrInvalidCredentials)
		}
		ath.log.Info("failed to generate passHash")
		return false, fmt.Errorf("%s: %w", opLogin, err)
	}

	if err := ath.authInterface.RecoverUser(ctx, usr.Id); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			ath.log.Warn("user not found")
			return false, fmt.Errorf("%s: %w", opDelete, ErrUserNotFound)
		}
		ath.log.Error("failed to recover user %w", err)
		return false, fmt.Errorf("%s: %w", opRecover, err)
	}

	return true, nil
}

func (ath *Auth) IsAdmin(
	ctx context.Context,
	userId int64,
) (bool, error) {
	ath.log.Info("Auth. Is admin.")

	isAdmin, err := ath.authInterface.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			ath.log.Warn("app not found")
			return false, fmt.Errorf("%s: %w", opIsAdmin, ErrInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", opIsAdmin, err)
	}

	return isAdmin, nil
}

func (ath *Auth) GenerateToken(ctx context.Context, user *models.User, appId int32) (string, error) {
	app, err := ath.authInterface.GetApp(ctx, appId)
	if err != nil {
		return "", err
	}

	return jwt.NewToken(models.User{
		Id:       user.Id,
		Email:    user.Email,
		Passhash: user.Passhash,
	}, app, ath.token)
}
