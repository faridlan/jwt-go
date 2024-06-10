package model

import "github.com/golang-jwt/jwt/v5"

type Claim struct {
	User User `json:"user,omitempty"`
	jwt.RegisteredClaims
}
