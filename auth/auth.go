package auth

import (
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
)

type AuthenticationHandler interface {
	HandleAuth(writer http.ResponseWriter, request *http.Request)
	HandleAuthStart(writer http.ResponseWriter, request *http.Request)
	HandleAuthCallback(writer http.ResponseWriter, request *http.Request)
}

var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(32))

func getSession(request *http.Request) sessions.Session {
	// TODO: where to check if session or token is expired?
	session, err := store.Get(request,"oauth2-session")
	if err != nil {
		// Ignore error as it just means we have a new random key.
		// Cookies will be overwritten using the new key.
		log.Printf("error getting session: %v", err)
	}

	session.Options.MaxAge = 8 * 3600
	session.Options.Secure = true
	session.Options.HttpOnly = true

	return *session
}
