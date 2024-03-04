package jwt

import (
	"errors"
	"fmt"
	"time"

	"example.com/m/sso/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
)

const (
	opVerify 	= "JWT. Verify token"
	opNewToken  = "JWT. New token"
)

var (
	ErrInvalidVerifyToken = errors.New("invalid token")
)

func NewToken(user models.User, app models.App, duration time.Duration) (string, error){
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.Id
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.Id

	tokenStr, err := token.SignedString([]byte(app.Secrete)) //FIXME: give secrete not through App, unit tests
	if err != nil {
		return "", fmt.Errorf("%s: %w", opNewToken, err)
	}
	
	return tokenStr, nil
}

func VerifyToken(tokenStr string) error {  
	iat, err := GetExpFromClaims(tokenStr)
	if err!= nil {
		return fmt.Errorf("%s: %w", opVerify, ErrInvalidVerifyToken)
	}

    tm  := time.Unix(int64(iat),0)
	
	if t := time.Now().Compare(tm); t != -1 {
		return fmt.Errorf("%s: %w", opVerify, ErrInvalidVerifyToken)
	}
	return nil
}
// GetExpFromClaims gets the expiration time from the claims.
func GetExpFromClaims(tokenStr string) (float64, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
    if err != nil {
        return 0, err
    }

	claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
		return 0, ErrInvalidVerifyToken   
	}

	return claims["exp"].(float64), nil
}