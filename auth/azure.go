package auth

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

type signInPageData struct {
	AuthUrl string
}

type AzureAuthenticationHandler struct {
	tenantId string
	clientId string
	callbackUrl string
	oidcProvider *oidc.Provider
	tokenVerifier *oidc.IDTokenVerifier
	userTokens map[string]string
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
		"https://login.microsoftonline.com/%s/v2.0",
		tenantId,
	)
}

func NewAzureAuthenticationHandler(
	tenantId string,
	clientId string,
	callbackUrl string,
) (*AzureAuthenticationHandler, error) {
	provider, err := oidc.NewProvider(context.Background(), issuerUrl(tenantId))
	if err != nil {
		return nil, err
	}

	handler := &AzureAuthenticationHandler{
		tenantId: tenantId,
		clientId: clientId,
		callbackUrl: callbackUrl,
		oidcProvider: provider,
		tokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
		userTokens: make(map[string]string),
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
	q.Add("response_type", "id_token")
	q.Add("redirect_uri", h.callbackUrl)
	q.Add("response_mode", "form_post")
	q.Add("scope", "openid")
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
func (h *AzureAuthenticationHandler) HandleAuthCallback(writer http.ResponseWriter, request *http.Request) {
	log.Printf("Callback, request: %+v", request)

	if request.Method != "POST" {
		http.Error(
			writer,
			fmt.Sprintf("callback method was %s, expected POST", request.Method),
			http.StatusBadRequest,
		)
		return
	}

	if err := request.ParseForm(); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	if authError, ok := request.Form["error"]; ok {
		// TODO: check array length both for error and description
		errorMsg := authError[0]

		if description, ok := request.Form["error_description"]; ok {
			errorMsg += ": " + description[0]
		}

		log.Printf("error authenticating: %s", errorMsg)
		// TODO: return correct error based on specific error
		http.Error(writer, errorMsg, http.StatusBadRequest)
		return
	}

	log.Printf("Callback, request form: %+v", request.Form)

	token, ok := request.Form["id_token"]
	if !ok || len(token) != 1 {
		http.Error(writer, "JWT not found", http.StatusBadRequest)
		return
	}

	idToken, err := h.tokenVerifier.Verify(context.Background(), token[0])
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

	err = validateState(request, session)
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

	h.userTokens[userKey] = token[0]

	// TODO: we might want to consider storing the redirect URL instead of always redirecting to /
	http.Redirect(writer, request, "/", 302)
}

// TODO: as multiple flash values can be appended, shall we instead look
//  that the state and nonce values
//  appear anywhere in the flash value list?

func validateState(request *http.Request, session sessions.Session) error {
	originalState := session.Flashes("state")

	if len(originalState) != 1 {
		return fmt.Errorf("state cookie is not present")
	}

	if state, ok := request.Form["state"]; ok && len(state) == 1 {
		if state[0] != originalState[0] {
			return fmt.Errorf("state values do not match")
		}
	} else {
		return fmt.Errorf("state not present in request")
	}

	return nil
}

func validateNonce(nonce string, session sessions.Session) error {
	originalNonce := session.Flashes("nonce")

	if len(originalNonce) != 1 {
		return fmt.Errorf("nonce cookie is not present")
	}

	if nonce != originalNonce[0] {
		return fmt.Errorf("nonce values do not match")
	}

	return nil
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
