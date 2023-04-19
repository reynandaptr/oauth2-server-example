package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	ginserver "github.com/go-oauth2/gin-server"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/sirupsen/logrus"
	pg "github.com/vgarvardt/go-oauth2-pg/v4"
	"github.com/vgarvardt/go-pg-adapter/pgx4adapter"
)

func main() {
	pgxConn, err := pgx.Connect(context.TODO(), os.Getenv("DB_URI"))
	if err != nil {
		logrus.Fatal(err)
	}

	manager := manage.NewDefaultManager()

	// use PostgreSQL token store with pgx.Connection adapter
	adapter := pgx4adapter.NewConn(pgxConn)
	tokenStore, _ := pg.NewTokenStore(adapter, pg.WithTokenStoreGCInterval(time.Minute))
	defer tokenStore.Close()

	clientStore, _ := pg.NewClientStore(adapter)

	manager.MapTokenStorage(tokenStore)
	manager.MapClientStorage(clientStore)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	ginserver.InitServer(manager)
	ginserver.SetAllowGetAccessRequest(true)
	ginserver.SetClientInfoHandler(server.ClientBasicHandler)

	ginserver.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		return "1", nil
	})

	ginserver.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	ginserver.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	g := gin.Default()
	auth := g.Group("/oauth2")
	auth.GET("/credentials", func(ctx *gin.Context) {
		clientId := uuid.New().String()[:8]
		clientSecret := uuid.New().String()[:8]
		err := clientStore.Create(&models.Client{
			ID:     clientId,
			Secret: clientSecret,
			Domain: "http://localhost:9094",
			UserID: "1",
		})
		if err != nil {
			fmt.Println(err.Error())
		}

		ctx.Header("Content-Type", "application/json")
		ctx.JSON(http.StatusOK, gin.H{"client_id": clientId, "client_secret": clientSecret})
	})
	auth.GET("/auth", ginserver.HandleAuthorizeRequest)
	auth.POST("/token", ginserver.HandleTokenRequest)
	auth.POST("/revocation", func(ctx *gin.Context) {
		accessToken := ctx.Request.FormValue("access_token")

		err := manager.RemoveAccessToken(context.TODO(), accessToken)
		if err != nil {
			logrus.Error("RemoveAccessToken", err)
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Success"})
	})

	g.GET("/protected", ginserver.HandleTokenVerify(ginserver.Config{
		ErrorHandleFunc: func(ctx *gin.Context, err error) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
			ctx.Abort()
		},
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "Hello, I'm protected"})
	})

	g.Run(":9096")
}
