package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"
)

type signInPageData struct {
	AuthUrl string
}

type AzureAuthenticationHandler struct {
	tenantId string
	clientId string
	clientSecret string
	callbackUrl string
	oidcProvider *oidc.Provider
	tokenVerifier *oidc.IDTokenVerifier
	userTokens map[string]string
	httpClient http.Client
}

const signInTemplateContent = `
<!DOCTYPE html>
<meta charset="utf-8">
<title>Authenticate</title>
<a href="{{.AuthUrl}}">Sign in with your Azure credentials</a>
`

var signInTemplate = template.Must(
	template.New("sign-in").Parse(signInTemplateContent))

func issuerUrl(tenantId string) string {
	return fmt.Sprintf(
		"https://sts.windows.net/%s/",
		tenantId,
	)
}

func NewAzureAuthenticationHandler(
	tenantId string,
	clientId string,
	clientSecret string,
	callbackUrl string,
) (*AzureAuthenticationHandler, error) {
	provider, err := oidc.NewProvider(context.Background(), issuerUrl(tenantId))
	if err != nil {
		return nil, err
	}

	handler := &AzureAuthenticationHandler{
		tenantId: tenantId,
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

func (h *AzureAuthenticationHandler) HandleAuth(writer http.ResponseWriter, request *http.Request) {
	if h.authenticated(request) {
		if token, err := h.getToken(request); err == nil {
			writer.Header().Set("X-Auth-Request-Access-Token", *token)
			writer.WriteHeader(http.StatusOK)
			return
		}
	}

	writer.WriteHeader(http.StatusUnauthorized)
}

func (h *AzureAuthenticationHandler) HandleAuthStart(writer http.ResponseWriter, request *http.Request) {
	state := uuid.New().String()
	nonce := uuid.New().String()

	session := getSession(request)
	session.AddFlash(state, "state")
	session.AddFlash(nonce, "nonce")
	err := session.Save(request, writer)
	if err != nil {
		HttpError(writer, err,
			"cannot save cookies", http.StatusInternalServerError)
		return
	}

	authUrl, err := url.Parse(h.oidcProvider.Endpoint().AuthURL)
	if err != nil {
		HttpError(writer, err,
			"cannot parse authorize URL", http.StatusInternalServerError)
		return
	}

	q := authUrl.Query()
	q.Add("client_id", h.clientId)
	q.Add("response_type", "code")
	q.Add("redirect_uri", h.callbackUrl)
	q.Add("response_mode", "form_post")
	q.Add("scope", "openid")
	q.Add("state", state)
	q.Add("nonce", nonce)
	q.Add("resource", fmt.Sprintf("spn:%s", h.clientId))
	authUrl.RawQuery = q.Encode()

	err = signInTemplate.Execute(writer, signInPageData{
		AuthUrl: authUrl.String(),
	})
	if err != nil {
		HttpError(writer, err,
			"error rendering sign-in page", http.StatusInternalServerError)
		return
	}
}

func (h *AzureAuthenticationHandler) HandleAuthCallback(writer http.ResponseWriter, request *http.Request) {
	log.Printf("Callback, request: %+v", request)

	if err := h.validateCallbackRequest(request); err != nil {
		HttpError(writer, err,
			"error authenticating", http.StatusBadRequest)
		return
	}

	code, ok := request.Form["code"]
	if !ok || len(code) != 1 {
		HttpError(writer, nil,
			"code not found", http.StatusBadRequest)
		return
	}

	resp, err := h.httpClient.PostForm(h.oidcProvider.Endpoint().TokenURL, url.Values{
		"code":          {code[0]},
		"client_id":     {h.clientId},
		"client_secret": {h.clientSecret},
		"redirect_uri":  {h.callbackUrl},
		"grant_type":    {"authorization_code"},
		"scope":         {"profile group openid"},
		"api-version":   {"1.0"},
	})
	if err != nil {
		HttpError(writer, err,
			"error obtaining token", http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		ExpiresIn    string `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		HttpError(writer, err,
			"error obtaining token", http.StatusInternalServerError)
		return
	}

	idToken, err := h.tokenVerifier.Verify(context.Background(), tokenResponse.IdToken)
	if err != nil {
		HttpError(writer, err,
			"error verifying token", http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email string `json:"email"`
		Nonce string `json:"nonce"`
	}

	if err := idToken.Claims(&claims); err != nil {
		HttpError(writer, err,
			"error obtaining token claims", http.StatusInternalServerError)
		return
	}

	session := getSession(request)

	err = validateNonce(claims.Nonce, session)
	if err != nil {
		HttpError(writer, err,
			"cannot validate nonce", http.StatusInternalServerError)
		return
	}

	userKey := uuid.New().String()
	session.Values["user"] = userKey

	err = session.Save(request, writer)
	if err != nil {
		HttpError(writer, err,
			"error saving session", http.StatusBadRequest)
		return
	}

	// IdToken does not have the 'spn:' prefix on the audience field; AccessToken does.
	h.userTokens[userKey] = tokenResponse.AccessToken

	// TODO: we might want to consider storing the redirect URL instead of always redirecting to /
	http.Redirect(writer, request, "/", 302)
}

func (h *AzureAuthenticationHandler) validateCallbackRequest(request *http.Request) error {
	if request.Method != "POST" {
		return fmt.Errorf("callback method was %s, expected POST", request.Method)
	}

	if err := request.ParseForm(); err != nil {
		return fmt.Errorf("error parsing form: %s", err.Error())
	}

	session := getSession(request)

	err := h.validateState(request, session)
	if err != nil {
		return fmt.Errorf("error validating state: %s", err.Error())
	}

	if errorMsg := h.extractCallbackError(request); errorMsg != nil {
		return fmt.Errorf("error authenticating: %s", *errorMsg)
	}

	return nil
}

func (h *AzureAuthenticationHandler) extractCallbackError(request *http.Request) *string {
	if authError, ok := request.Form["error"]; ok {
		errorMsg := "unknown_error"
		if len(authError) > 0 {
			errorMsg = authError[0]
		}
		if description, ok := request.Form["error_description"]; ok {
			if len(description) > 0 {
				errorMsg += ": " + description[0]
			}
		}
		return &errorMsg
	}

	return nil
}

func (h *AzureAuthenticationHandler) validateState(request *http.Request, session sessions.Session) error {
	originalState := session.Flashes("state")

	if len(originalState) == 0 {
		return fmt.Errorf("state cookie is not present")
	}

	if state, ok := request.Form["state"]; ok && len(state) == 1 {
		for _, s := range originalState {
			if state[0] == s {
				return nil
			}
		}
		return fmt.Errorf("state values do not match")
	}

	return fmt.Errorf("state not present in request")
}

func validateNonce(nonce string, session sessions.Session) error {
	originalNonce := session.Flashes("nonce")

	if len(originalNonce) == 0 {
		return fmt.Errorf("nonce cookie is not present")
	}

	for _, n := range originalNonce {
		if nonce == n {
			return nil
		}
	}

	return fmt.Errorf("nonce values do not match")
}

func (h *AzureAuthenticationHandler) authenticated(request *http.Request) bool {
	session := getSession(request)

	if userKey, ok := session.Values["user"]; ok {
		// TODO: shall we check the token has not expired yet?
		_, ok = h.userTokens[userKey.(string)]
		return ok
	}

	return false
}

func (h *AzureAuthenticationHandler) getToken(request *http.Request) (*string, error) {
	session := getSession(request)

	if userKey, ok := session.Values["user"]; ok {
		if token, ok := h.userTokens[userKey.(string)]; ok {
			return &token, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}
