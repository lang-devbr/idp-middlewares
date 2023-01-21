package middlewares

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func AuthJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		const BEARER_SCHEMA = "Bearer "
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			log.Println("authorization header not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[len(BEARER_SCHEMA):]

		if tokenString == "" {
			log.Println("token not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		token, err := validateToken(tokenString)

		if err != nil {
			log.Println("error parsing token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			log.Println("Claims[Name]: ", claims["name"])
			log.Println("Claims[Admin]: ", claims["admin"])
			log.Println("Claims[Issuer]: ", claims["iss"])
			log.Println("Claims[IssuedAt]: ", claims["iat"])
			log.Println("Claims[ExpiresAt]: ", claims["exp"])
		} else {
			log.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func ValidateEmail(tokenString, email string) bool {
	const BEARER_SCHEMA = "Bearer "

	if tokenString == "" {
		return false
	}

	tokenString = tokenString[len(BEARER_SCHEMA):]

	if tokenString == "" {
		return false
	}

	token, err := validateToken(tokenString)
	if err != nil {
		return false
	}

	if token.Valid {
		claims := token.Claims.(jwt.MapClaims)
		emailToken := claims["name"].(string)

		if emailToken == email {
			return true
		}
	}

	return false
}

func validateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		secret, err := getSecret()
		if err != nil {
			return nil, fmt.Errorf("error to validate token: %s", err.Error())
		}

		return []byte(secret), nil
	})
}

func getSecret() (string, error) {
	v := os.Getenv("IDP_SECRET")
	if v == "" {
		return "", errors.New("idp secret not found")
	}

	return v, nil
}
