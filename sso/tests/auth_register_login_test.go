package tests

import (
	"testing"
	"time"

	ssov1 "example.com/m/protos/gen/go/sso"
	"example.com/m/sso/tests/suite"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const(
	emptyAppId = 0
	appId = 1
	appSecret = "test-secret"

	passLenDefault = 10
)

func TestRegisterLogin_Login_HappyPath(test *testing.T){
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()

	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email: email,
		Password: password,
		AppId: appId,
	})
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	responseLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email: email,
		Password: password,
		AppId: appId,
	})
	require.NoError(test, err)

	loginTime := time.Now() //the beginning of the token's life

	token := responseLogin.GetToken()
	require.NotEmpty(test, token)

	tokenPars, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(test, err)

	claims, ok := tokenPars.Claims.(jwt.MapClaims)
	assert.True(test, ok)

	assert.Equal(test, email, claims["email"].(string))
	assert.Equal(test, appId, int(claims["app_id"].(float64)))

	const deltaSecond = 1 //error rate

	assert.InDelta(test, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSecond)
}

func TestRegisterLoginDuplicated(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()

	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email: email,
		Password: password,
		AppId: appId,
	})
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	responseRegister, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email: email,
		Password: password,
	})
	require.Error(test, err)
	assert.Empty(test, responseRegister.GetToken())
	assert.ErrorContains(test, err, "user already exis")
}

func TestUpdatePassword_HappyPath(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()
	passwordChenged := randomPassword()

	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
        Email: email,
        Password: password,
		AppId: appId,
    })
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	responseUpdatePassword, err := st.AuthClient.Update(ctx, &ssov1.UpdateRequest{
        Token: responseRegister.GetToken(),
		Password: passwordChenged,
		AppId: appId,
    })
	require.NoError(test, err)
	assert.NotEmpty(test, responseUpdatePassword.GetToken())
}

func TestDeleteRecover_HappyPath(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()

	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
        Email: email,
        Password: password,
		AppId: appId,
    })
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	responseDelete, err := st.AuthClient.Delete(ctx, &ssov1.DeleteRequest{
		Token: responseRegister.GetToken(),
	})
	require.NoError(test, err)
	assert.True(test, responseDelete.GetIsDelete())

	responseRecover, err := st.AuthClient.Recover(ctx, &ssov1.RecoverRequest{
        Email: email,
		Password: password,
    })
	require.NoError(test, err)
	assert.True(test, responseRecover.GetIsRecover())
}

func TestRegister_FailCase(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	tests := []struct {
		name        string
		email       string
		password    string
		AppID       int32
		expectedErr string
	}{
		{
			name:        "Register with empty Password",
			email:       gofakeit.Email(),
			password:    "",
			AppID: appId,
			expectedErr: "password is required",
		},
		{
			name:        "Register with empty email",
			email:       "",
			password:    randomPassword(),
			AppID:  appId,
			expectedErr: "email is required",
		},
		{
			name:        "Register with both empty",
			email:       "",
			password:    "",
			AppID: emptyAppId,
			expectedErr: "email is required",
		},
		{
			name:        "Register with Non-Matching AppID",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			AppID: -1,
			expectedErr: "invalid app id",
		},
		{
			name:        "Register without AppID",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			AppID: emptyAppId,
			expectedErr: "invalid app id",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email: tt.email,
				Password: tt.password,
				AppId: tt.AppID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestLogin_FailCase(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appId,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomPassword(),
			appID:       appId,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			email:       "",
			password:    "",
			appID:       appId,
			expectedErr: "email is required",
		},
		{
			name:        "Login without AppID",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			appID:       emptyAppId,
			expectedErr: "app id is required",
		},
		{
			name:        "Login invalid Email",
			email:       "email-NotValid",
			password:    randomPassword(),
			appID:       emptyAppId,
			expectedErr: "app id is required",
		},
	}
	tests2 := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Non-Matching Password",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			appID:       appId,
			expectedErr: "invalid email or password",
		},
		{
			name:        "Login with Non-Matching AppID",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			appID:       -1,
			expectedErr: "invalid app id",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email: gofakeit.Email(),
				Password: randomPassword(),
				AppId: appId,
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email: tt.email,
				Password: tt.password,
				AppId: tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
	for _, tt := range tests2 {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email: tt.email,
				Password: tt.password,
				AppId: appId,
			})
			require.NoError(t, err)

			if tt.name == "Login with Non-Matching Password" {
				tt.password = "INVALID-PASSWORD"
			}
			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email: tt.email,
				Password: tt.password,
				AppId: tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestUpdatePassword_FailCase(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()

	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
        Email: email,
        Password: password,
		AppId: appId,
    })
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	token := responseRegister.GetToken()

	tests := []struct {
		name        string
		Token       string
		passwordChanged string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Update with Empty Passwords",
			Token: token,
			passwordChanged: "",
			appID:       appId,
			expectedErr: "password is required",
		},
		{
			name:        "Update with Empty AppID",
			Token:       token,
			passwordChanged: randomPassword(),
			appID:       emptyAppId,
			expectedErr: "app id is required",
		},
		{
			name:        "Update with Empty Token",
			Token: "",
			passwordChanged: randomPassword(),
			appID:       appId,
			expectedErr: "token is required",
		},
		{
			name:        "Update with Both Empty Total",
			Token:       "",
			passwordChanged: "",
			appID:       emptyAppId,
			expectedErr: "token is required",
		},
		{
			name:        "Update with Non-Matching Token",
			Token: "invalid-token",
			passwordChanged: password,
			appID:       appId,
			expectedErr: "invalid token",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Update(ctx, &ssov1.UpdateRequest{
				Token: tt.Token,
				Password: tt.passwordChanged,
                AppId: tt.appID,
            })
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestDelete_FailCase(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	email := gofakeit.Email()
	password := randomPassword()
	responseRegister, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
        Email: email,
        Password: password,
		AppId: appId,
    })
	require.NoError(test, err)
	assert.NotEmpty(test, responseRegister.GetToken())

	tests := []struct {
		name        string
        token       string
        expectedErr string
    }{
		{
			name:        "Delete with Empty Token",
            token: "",
            expectedErr: "token is required",
		},
		{
			name:        "Delete with Invalid Token",
            token: "not-valid-token",
            expectedErr: "invalid token",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Delete(ctx, &ssov1.DeleteRequest{
				Token: tt.token,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestRecover_FailCase(test *testing.T)  {
	ctx, st := suite.NewSuit(test)

	tests := []struct {
		name        string
        email       string
		password    string
        expectedErr string
    }{
		{
			name:        "Delete with Empty Password",
            email: gofakeit.Email(),
			password: "",
            expectedErr: "password is required",
		},
		{
			name:        "Delete with Empty Email",
            email: "",
			password: randomPassword(),
            expectedErr: "email is required",
		},
		{
			name:        "Delete with Empty Both",
            email: "",
			password: "",
            expectedErr: "email is required",
		},
		{
			name:        "Delete with Invalid Arguments",
			email: gofakeit.Email(),
			password: randomPassword(),
			expectedErr: "user not found",
		},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Recover(ctx, &ssov1.RecoverRequest{
				Email: tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomPassword() string{
	return gofakeit.Password(true, true, true, true, false, passLenDefault)
}