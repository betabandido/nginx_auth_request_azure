package main

import (
	"flag"
	"github.com/betabandido/nginx_auth_request_azure/auth"
	"net/http"
	"os"
	"time"
)

func main() {
	flagSet := flag.NewFlagSet("nginx_auth_request_azure", flag.ExitOnError)

	tenantId := flagSet.String(
		"tenant-id",
		"",
		"Tenant Id")

	clientId := flagSet.String(
		"client-id",
		os.Getenv("NGINX_AUTH_AZURE_CLIENT_ID"),
		"Client Id",
	)

	clientSecret := flagSet.String(
		"client-secret",
		os.Getenv("NGINX_AUTH_AZURE_CLIENT_SECRET"),
		"Client Secret",
	)

	callbackUrl := flagSet.String(
		"callback-url",
		"",
		"Callback URL",
	)

	address := flagSet.String(
		"address",
		":4180",
		"Address to listen on",
	)

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if *tenantId == "" || *clientId == "" || *clientSecret == "" || *callbackUrl == "" {
		flagSet.Usage()
		os.Exit(1)
	}

	handler, err := auth.NewAzureAuthenticationHandler(
		*tenantId,
		*clientId,
		*callbackUrl,
	)
	//handler, err := auth.NewGoogleAuthenticationHandler(
	//	*clientId,
	//	*clientSecret,
	//	*callbackUrl,
	//)
	if err != nil {
		panic(err)
	}

	server := http.Server{
		Addr: *address,
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	http.HandleFunc("/oauth2/auth", handler.HandleAuth)
	http.HandleFunc("/oauth2/start", handler.HandleAuthStart)
	http.HandleFunc("/oauth2/callback", handler.HandleAuthCallback)

	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
