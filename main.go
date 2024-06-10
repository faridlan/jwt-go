package main

import (
	"fmt"

	"github.com/faridlan/jwt-go/config"
	"github.com/faridlan/jwt-go/model"
)

func main() {

	user := model.User{
		Username: "nullhakim",
		Email:    "nullhakim@mail.com",
	}

	claims := model.Claim{
		User: user,
	}

	token, err := config.GenerateJWT(&claims)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)

}
