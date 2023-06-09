package main

import (
	"auth-refresh-token-flow/handler"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.POST("/token", handler.RefreshToken)
	e.Start(":1323")
}
