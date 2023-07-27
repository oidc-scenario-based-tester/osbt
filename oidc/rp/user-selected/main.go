package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

var (
	callbackPath = "/auth/callback"
	key          = []byte("test1234test1234")
	rps          = make(map[string]*rp.RelyingParty)
)

func generateStateWithIssuer(issuer string) func() string {
	return func() string {
		state := uuid.New().String()
		return state + ":" + issuer
	}
}

func getRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI string, scopes []string, options ...rp.Option) (*rp.RelyingParty, error) {
	// if rp, ok := rps[issuer]; ok { // if instance already exists, return it
	// 	return rp, nil
	// }

	rp, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...) // otherwise create a new instance
	if err != nil {
		return nil, err
	}

	// rps[issuer] = &rp // save the instance in the map
	return &rp, nil
}

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	port := os.Getenv("PORT")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	// provider, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
	// if err != nil {
	// 	logrus.Fatalf("error creating provider %s", err.Error())
	// }

	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	// state := func() string {
	// 	return uuid.New().String()
	// }

	// register the AuthURLHandler at your preferred path.
	// the AuthURLHandler creates the auth request and redirects the user to the auth server.
	// including state handling with secure cookie and the possibility to use PKCE.
	// Prompts can optionally be set to inform the server of
	// any messages that need to be prompted back to the user.
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		issuer := r.URL.Query().Get("issuer")
		log.Printf("issuer: %s", issuer)
		if issuer == "" {
			http.Error(w, "Issuer not provided", http.StatusBadRequest)
			return
		}

		provider, err := getRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rp.AuthURLHandler(generateStateWithIssuer(issuer), *provider, rp.WithPromptURLParam("Welcome back!")).ServeHTTP(w, r)
	})

	// for demonstration purposes the returned userinfo response is written as JSON object onto response
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	// you could also just take the access_token and id_token without calling the userinfo endpoint:
	//
	// marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
	//	data, err := json.Marshal(tokens)
	//	if err != nil {
	//		http.Error(w, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//	w.Write(data)
	//}

	// you can also try token exchange flow
	//
	// requestTokenExchange := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {
	// 	data := make(url.Values)
	// 	data.Set("grant_type", string(oidc.GrantTypeTokenExchange))
	// 	data.Set("requested_token_type", string(oidc.IDTokenType))
	// 	data.Set("subject_token", tokens.RefreshToken)
	// 	data.Set("subject_token_type", string(oidc.RefreshTokenType))
	// 	data.Add("scope", "profile custom_scope:impersonate:id2")

	// 	client := &http.Client{}
	// 	r2, _ := http.NewRequest(http.MethodPost, issuer+"/oauth/token", strings.NewReader(data.Encode()))
	// 	// r2.Header.Add("Authorization", "Basic "+"d2ViOnNlY3JldA==")
	// 	r2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// 	r2.SetBasicAuth("web", "secret")

	// 	resp, _ := client.Do(r2)
	// 	fmt.Println(resp.Status)

	// 	b, _ := io.ReadAll(resp.Body)
	// 	resp.Body.Close()

	// 	w.Write(b)
	// }

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	// in this example the callback function itself is wrapped by the UserinfoCallback which
	// will call the Userinfo endpoint, check the sub and pass the info into the callback function
	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		stateParam := r.URL.Query().Get("state")
		log.Printf("state: %s", stateParam)
		if stateParam == "" {
			http.Error(w, "State not provided", http.StatusBadRequest)
			return
		}

		firstIndex := strings.Index(stateParam, ":")
		if firstIndex == -1 || firstIndex == len(stateParam)-1 {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		issuer := stateParam[firstIndex+1:]

		provider, err := getRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), *provider).ServeHTTP(w, r)
	})

	// if you would use the callback without calling the userinfo endpoint, simply switch the callback handler for:
	//
	// http.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	logrus.Infof("listening on http://%s/", lis)
	logrus.Info("press ctrl+c to stop")
	logrus.Fatal(http.ListenAndServe(lis, nil))
}
