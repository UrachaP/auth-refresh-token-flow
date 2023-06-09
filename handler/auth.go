package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

const (
	RefreshTokenDuration = 48 * time.Hour
	AccessTokenDuration  = 1 * time.Hour
	SecretKey            = "secret"
)

type Token struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func RefreshToken(c echo.Context) error {
	refreshToken := c.Request().Header.Get("refresh_token")
	if refreshToken == "" {
		return c.JSON(http.StatusBadRequest, errors.New("refresh token is required"))
	}

	token, err := decodeToken(refreshToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	accessToken, err := generateToken(token.Subject, AccessTokenDuration)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	refreshToken, err = generateToken(token.Subject, RefreshTokenDuration)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, Token{RefreshToken: refreshToken, AccessToken: accessToken})
}

func decodeToken(token string) (jwt.StandardClaims, error) {
	claims := jwt.StandardClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	return claims, err
}

func generateToken(userId string, duration time.Duration) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   userId,
		ExpiresAt: time.Now().Add(duration).Unix()}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(SecretKey))
	return tokenString, err
}
