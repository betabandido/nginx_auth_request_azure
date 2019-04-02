package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"net/url"
	"time"
)

type GoogleAuthenticationHandler struct {
	clientId string
	clientSecret string
	callbackUrl string
	oidcProvider *oidc.Provider
	tokenVerifier *oidc.IDTokenVerifier
	userTokens map[string]string
	httpClient http.Client
}

func googleIssuerUrl() string {
	return "https://accounts.google.com"
}

func NewGoogleAuthenticationHandler(
	clientId string,
	clientSecret string,
	callbackUrl string,
) (*GoogleAuthenticationHandler, error) {
	provider, err := oidc.NewProvider(context.Background(), googleIssuerUrl())
	if err != nil {
		return nil, err
	}

	handler := &GoogleAuthenticationHandler{
		clientId: clientId,
		clientSecret: clientSecret,
		callbackUrl: callbackUrl,
		oidcProvider: provider,
		tokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
		userTokens: make(map[string]string),
		httpClient: http.Client{
			Timeout: time.Second * 10,
		},
	}

	return handler, nil
}

func (h *GoogleAuthenticationHandler) HandleAuth(writer http.ResponseWriter, request *http.Request) {
	if h.authenticated(request) {
		if token, err := h.getToken(request); err == nil {
			writer.Header().Set("X-Auth-Request-Access-Token", *token)
			writer.WriteHeader(http.StatusOK)
			return
		}
	}

	writer.WriteHeader(http.StatusUnauthorized)
}

func (h *GoogleAuthenticationHandler) HandleAuthStart(writer http.ResponseWriter, request *http.Request) {
	authUrl, err := url.Parse(h.oidcProvider.Endpoint().AuthURL)
	if err != nil {
		log.Print("Error while parsing authorize URL: ", err.Error())
		http.Error(writer, "cannot parse authorize URL", http.StatusInternalServerError)
		return
	}

	state := uuid.New().String()
	nonce := uuid.New().String()

	session := getSession(request)
	session.AddFlash(state, "state")
	session.AddFlash(nonce, "nonce")
	err = session.Save(request, writer)
	if err != nil {
		log.Print("Error while saving flash cookies: ", err.Error())
		http.Error(writer, "cannot save cookies", http.StatusInternalServerError)
		return
	}

	q := authUrl.Query()
	q.Add("client_id", h.clientId)
	q.Add("response_type", "code")
	q.Add("redirect_uri", h.callbackUrl)
	q.Add("scope", "openid email profile")
	q.Add("state", state)
	q.Add("nonce", nonce)
	authUrl.RawQuery = q.Encode()

	err = signInTemplate.Execute(writer, signInPageData{
		AuthUrl: authUrl.String(),
	})
	if err != nil {
		log.Print("Error while rendering the sign-in page: ", err.Error())
		http.Error(writer, "error rendering sign-in page", http.StatusInternalServerError)
		return
	}
}

// TODO: on error should we simply redirect to an error page?
func (h *GoogleAuthenticationHandler) HandleAuthCallback(writer http.ResponseWriter, request *http.Request) {
	log.Printf("Callback, request: %+v", request)

	if request.Method != "GET" {
		http.Error(
			writer,
			fmt.Sprintf("callback method was %s, expected GET", request.Method),
			http.StatusBadRequest,
		)
		return
	}

	code := request.URL.Query().Get("code")

	resp, err := h.httpClient.PostForm(h.oidcProvider.Endpoint().TokenURL, url.Values{
		"code": {code},
		"client_id": {h.clientId},
		"client_secret": {h.clientSecret},
		"redirect_uri": {h.callbackUrl},
		"grant_type": {"authorization_code"},
	})
	if err != nil {
		http.Error(
			writer,
			fmt.Sprintf("error obtaining token"),
			http.StatusInternalServerError,
		)
		return
	}

	log.Printf("resp: %+v", resp)

	defer resp.Body.Close()

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		IdToken string `json:"id_token"`
		ExpiresIn int64 `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Printf(err.Error())
		http.Error(
			writer,
			fmt.Sprintf("error obtaining token"),
			http.StatusInternalServerError,
		)
		return
	}

	log.Printf("Token: %v", tokenResponse.IdToken)

	idToken, err := h.tokenVerifier.Verify(context.Background(), tokenResponse.IdToken)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	var claims struct {
		Email string `json:"email"`
		Nonce string `json:"nonce"`
	}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	session := getSession(request)

	err = h.validateState(request, session)
	if err != nil {
		http.Error(writer, "cannot validate state", http.StatusBadRequest)
		return
	}

	err = validateNonce(claims.Nonce, session)
	if err != nil {
		http.Error(writer, "cannot validate nonce", http.StatusBadRequest)
		return
	}

	userKey := uuid.New().String()
	session.Values["user"] = userKey

	err = session.Save(request, writer)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	h.userTokens[userKey] = tokenResponse.IdToken

	// TODO: we might want to consider storing the redirect URL instead of always redirecting to /
	http.Redirect(writer, request, "/", 302)
}

func (h *GoogleAuthenticationHandler) authenticated(request *http.Request) bool {
	session := getSession(request)

	if userKey, ok := session.Values["user"]; ok {
		// TODO: shall we check the token has not expired yet?
		_, ok = h.userTokens[userKey.(string)]
		return ok
	}

	return false
}

func (h *GoogleAuthenticationHandler) getToken(request *http.Request) (*string, error) {
	session := getSession(request)

	if userKey, ok := session.Values["user"]; ok {
		if token, ok := h.userTokens[userKey.(string)]; ok {
			return &token, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}

func (h *GoogleAuthenticationHandler) validateState(request *http.Request, session sessions.Session) error {
	originalState := session.Flashes("state")

	if len(originalState) != 1 {
		return fmt.Errorf("state cookie is not present")
	}

	state := request.URL.Query().Get("state")

	if state != originalState[0] {
		return fmt.Errorf("state values do not match")
	}

	return nil
}