package models

import "database/sql"

type User struct{
	Id int64
	Email string
	Passhash []byte
	Del bool
}

type UserDTO struct {
	AppId int32
	Email string
    Password string
}

type TokenCreateDTO struct {
	Id int64
	Tx *sql.Tx
}

type UserUpdateDTO struct {
	AppId int32
	Token string
	Password string
}
type UserDeleteDTO struct {
	Token string
}

type UserRecoverDTO struct {
    Email string
	Password string
}