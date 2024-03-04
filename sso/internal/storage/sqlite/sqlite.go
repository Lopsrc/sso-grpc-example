package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"example.com/m/sso/internal/domain/models"
	"example.com/m/sso/internal/storage"
	"github.com/mattn/go-sqlite3"
)

const (
	opAdd         = "DB.AddUser"
	opGet         = "DB.GetUser"
	opUpdate      = "DB.UpdateUser"
	opDelete      = "DB.DeleteUser"
	opRecover     = "DB.RecoverUser"
	opIsAdmin     = "DB.IsAdmin"
	opGetApp      = "DB.GetApp"
	opGetToken    = "DB.GetToken"
	opCreateToken = "DB.CreateToken"
)

type Storage struct {
	db *sql.DB
}

func NewDB(storagePath string) (*Storage, error) {

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("DB.constructor: %w", err)
	}

	return &Storage{
		db: db,
	}, nil
}

func (s *Storage) AddUser(ctx context.Context, email string, passHash []byte) (models.TokenCreateDTO, error) {
	query := "INSERT INTO users(email, pass_hash) VALUES(?,?)"

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if err = tx.Rollback(); err != nil {
			return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
		}
		return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
	}

	stmt, err := tx.Prepare(query)
	if err != nil {
		if err = tx.Rollback(); err != nil {
			return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
		}
		return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
	}

	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			if err = tx.Rollback(); err != nil {
				return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
			}
			return models.TokenCreateDTO{}, fmt.Errorf("%s.query: %w", opAdd, storage.ErrUserExist)
		}
		if err = tx.Rollback(); err != nil {
			return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
		}
		return models.TokenCreateDTO{}, fmt.Errorf("%s.query: %w", opAdd, err)
	}

	userId, err := res.LastInsertId()
	if err != nil {
		if err = tx.Rollback(); err != nil {
			return models.TokenCreateDTO{}, fmt.Errorf("%s: %w", opAdd, err)
		}
		return models.TokenCreateDTO{}, fmt.Errorf("%s.getId: %w", opAdd, err)
	}

	return models.TokenCreateDTO{
		Id: userId,
		Tx: tx,
	}, nil
}

func (s *Storage) CreateToken(ctx context.Context, user models.TokenCreateDTO, token string) error {
	defer user.Tx.Rollback()
	query := "INSERT INTO tokens(id_user, access_token) VALUES(?,?)"

	stmt, err := user.Tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opCreateToken, err)
	}

	_, err = stmt.ExecContext(ctx, user.Id, token)
	if err != nil {
		return fmt.Errorf("%s.query: %w", opCreateToken, err)
	}
	if err = user.Tx.Commit(); err != nil {
		return fmt.Errorf("%s: %w", opCreateToken, err)
	}
	return nil
}

func (s *Storage) LoginUser(ctx context.Context, userId int64, token string) error {
	query := "UPDATE tokens SET access_token =? WHERE id_user =?"
	stmt, err := s.db.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opGet, err)
	}

	_, err = stmt.ExecContext(ctx, token, userId)
	if err != nil {
		return fmt.Errorf("%s.query: %w", opGet, err)
	}

	return nil
}

func (s *Storage) UpdateUser(ctx context.Context, userId int64, passhash []byte, token string) error {
	query := "UPDATE users SET pass_hash=? WHERE id=?"

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", opUpdate, err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opUpdate, err)
	}

	_, err = stmt.ExecContext(ctx, passhash, userId)
	if err != nil {
		return fmt.Errorf("%s: %w", opUpdate, err)
	}

	query = "UPDATE tokens SET access_token =? WHERE id_user =?"
	stmt, err = tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opGet, err)
	}

	_, err = stmt.ExecContext(ctx, token, userId)
	if err != nil {
		return fmt.Errorf("%s.query: %w", opGet, err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("%s: %w", opUpdate, err)
	}
	return nil
}

func (s *Storage) DeleteUser(ctx context.Context, userId int64) error {
	query := "UPDATE users SET del=? WHERE id=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opDelete, err)
	}

	_, err = stmt.ExecContext(ctx, true, userId)
	if err != nil {
		return fmt.Errorf("%s: %w", opDelete, err)
	}
	return nil
}

func (s *Storage) RecoverUser(ctx context.Context, userId int64) error {
	query := "UPDATE users SET del=? WHERE id=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return fmt.Errorf("%s: %w", opRecover, err)
	}

	_, err = stmt.ExecContext(ctx, false, userId)
	if err != nil {
		return fmt.Errorf("%s: %w", opRecover, err)
	}
	return nil
}

func (s *Storage) IsAdmin(ctx context.Context, useId int64) (bool, error) {
	query := "SELECT is_admin FROM users WHERE id=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return false, fmt.Errorf("%s: %w", opIsAdmin, err)
	}

	row := stmt.QueryRowContext(ctx, useId)

	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", opIsAdmin, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", opIsAdmin, err)
	}
	return isAdmin, nil
}

func (s *Storage) GetUser(ctx context.Context, email string) (models.User, error) {
	var user models.User
	query := "SELECT id, email, pass_hash, del FROM users WHERE email=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return user, fmt.Errorf("%s: %w", opGet, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	err = row.Scan(&user.Id, &user.Email, &user.Passhash, &user.Del)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, fmt.Errorf("%s: %w", opGet, storage.ErrUserNotFound)
		}
		return user, fmt.Errorf("%s: %w", opGet, err)
	}
	return user, nil
}

func (s *Storage) GetUserById(ctx context.Context, userId int64) (models.User, error) {
	var user models.User
	query := "SELECT id, email, pass_hash FROM users WHERE id=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return user, fmt.Errorf("%s: %w", opGet, err)
	}

	row := stmt.QueryRowContext(ctx, userId)

	err = row.Scan(&user.Id, &user.Email, &user.Passhash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, fmt.Errorf("%s: %w", opGet, storage.ErrUserNotFound)
		}
		return user, fmt.Errorf("%s: %w", opGet, err)
	}
	return user, nil
}

func (s *Storage) GetApp(ctx context.Context, appId int32) (models.App, error) {
	query := "SELECT * FROM apps WHERE id=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", opGetApp, err)
	}

	row := stmt.QueryRowContext(ctx, appId)

	var app models.App
	err = row.Scan(&app.Id, &app.Name, &app.Secrete)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return app, fmt.Errorf("%s: %w", opGetApp, storage.ErrAppNotFound)
		}
		return app, fmt.Errorf("%s: %w", opGetApp, err)
	}
	return app, nil
}

func (s *Storage) GetUserIdbyToken(ctx context.Context, token string) (int64, error) { 
	query := "SELECT id_user FROM tokens WHERE access_token=?"

	stmt, err := s.db.Prepare(query)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", opGetToken, err)
	}

	row := stmt.QueryRowContext(ctx, token)

	var userId int64
	err = row.Scan(&userId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("%s: %w", opGetToken, storage.ErrTokenNotFound)
		}
		return 0, fmt.Errorf("%s: %w", opGetToken, err)
	}

	return userId, nil
}
