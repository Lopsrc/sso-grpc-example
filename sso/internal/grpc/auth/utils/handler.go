package utils

import (
	"fmt"
	"net/mail"

	ssov1 "example.com/m/protos/gen/go/sso"
)

const (
	emptyVar = 0
    tokenSize = 171
)

// ValidateRegisterRequest validates the RegisterRequest. Returns the "" and nil if the request is valid.
func ValidateRegisterRequest(req *ssov1.RegisterRequest) (string, error) {
    strError, isEmpty := RegisterFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    if  _, err := mail.ParseAddress(req.GetEmail()); err!= nil {
        return "invalid credentials", err
    }
    return "", nil
}
// ValidateLoginRequest validates the LoginRequest. Returns the "" and nil if the request is valid.
func ValidateLoginRequest(req *ssov1.LoginRequest) (string, error) {
    strError, isEmpty := LoginFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    if  _, err := mail.ParseAddress(req.GetEmail()); err!= nil {
        return "invalid credentials", err
    }
    return "", nil
}
// ValidateUpdateRequest validates the UpdateRequest. Returns the "" and nil if the request is valid.
func ValidateUpdateRequest(req *ssov1.UpdateRequest) (string, error) {
    strError, isEmpty := UpdateFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    return "", nil
}
// ValidateDeleteRequest validates the DeleteRequest. Returns the "" and nil if the request is valid.
func ValidateDeleteRequest(req *ssov1.DeleteRequest) (string, error) {
    strError, isEmpty := DeleteFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    return "", nil
}
// ValidateRecoverRequest validates the RecoverRequest. Returns the "" and nil if the request is valid.
func ValidateRecoverRequest(req *ssov1.RecoverRequest) (string, error) {
    strError, isEmpty := RecoverFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    if  _, err := mail.ParseAddress(req.GetEmail()); err!= nil {
        return "invalid credentials", err
    }
    return "", nil
}
// ValidateIsAdminRequest validates the IsAdminRequest. Returns the "" and nil if the request is valid 
func ValidateIsAdminRequest(req *ssov1.IsAdminRequest) (string, error) {
    strError, isEmpty := IsAdminFieldIsEmpty(req)
    if isEmpty {
        return strError, fmt.Errorf(strError)
    }
    return "", nil
}

// RegisterFieldIsEmpty checks if the RegisterRequest is empty.
func RegisterFieldIsEmpty(req *ssov1.RegisterRequest) (string, bool) {
	if req.GetEmail() == "" {
        return "email is required", true 
    }
    if req.GetPassword() == "" {
        return "password is required.", true 
    }
    return "", false
}
// LoginFieldIsEmpty checks if the LoginRequest is empty.
func LoginFieldIsEmpty(req *ssov1.LoginRequest) (string, bool) {
	if req.GetEmail() == "" {
        return "email is required", true
    }
    if req.GetPassword() == "" {
        return "password is required", true
    }
	if req.GetAppId() == emptyVar {
		return "app id is required", true
	}
    return "", false
}
// UpdateFieldIsEmpty checks if the UpdateRequest is empty.
func UpdateFieldIsEmpty(req *ssov1.UpdateRequest) (string, bool) {
	
    if req.GetToken() == "" {
        return "token is required", true 
    }
    if req.GetPassword() == "" {
        return "password is required", true 
    }
    if req.GetAppId() == emptyVar {
        return "app id is required" , true 
    }
    return "", false
}
// DeleteFieldIsEmpty checks if the DeleteRequest is empty.
func DeleteFieldIsEmpty(req *ssov1.DeleteRequest) (string, bool) {
	if req.GetToken() == "" {
        return "token is required", true 
    }
    return "", false
}
// RecoverFieldIsEmpty checks if the RecoverRequest is empty.
func RecoverFieldIsEmpty(req *ssov1.RecoverRequest) (string, bool) {
	if req.GetEmail() == "" {
        return "email is required" , true 
    }
    if req.GetPassword() == "" {
        return "password is required" , true 
    }
    return "", false
}
// IsAdminFieldIsEmpty checks if the IsAdminRequest is empty.
func IsAdminFieldIsEmpty(req *ssov1.IsAdminRequest) (string, bool) {
	if req.GetUserId() == emptyVar {
        return "user id is required", true 
    }
    return "", false
}