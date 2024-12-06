package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func main() {
	const clientId string = ""
	const clientSecret string = ""

	scopes := []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}

	startOAuthCodeFlow(clientId, clientSecret, scopes)
}

func startOAuthCodeFlow(clientId string, clientSecret string, scopes []string) {
	port, code := listenOAuthRedirectUrlCode()

	verifier, err := generateOAuthCodeVerifier()
	if err != nil {
		panic(err)
	}

	redirectUri := fmt.Sprintf("http://localhost:%d", port)

	challenge, method := generateOAuthCodeChallenge(verifier)
	authUrl := generateOAuthAuthorizationUrl(OAuthAuthorizationParams{
		ClientId:            clientId,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		RedirectUri:         redirectUri,
		Scope:               scopes,
	})

	fmt.Println(authUrl)

	accessToken := getOAuthAccessToken(OAuthTokenParams{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Code:         <-code,
		Verifier:     verifier,
		RedirectUri:  redirectUri,
	})

	fmt.Printf("Access token: %s\n", accessToken)
}

func generateOAuthCodeVerifier() (string, error) {
	const length int = 64

	verifier := make([]byte, length)
	_, err := rand.Read(verifier)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

func generateOAuthCodeChallenge(verifier string) (string, string) {
	const method string = "S256"

	hash := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(hash[:]), method
}

type OAuthAuthorizationParams struct {
	ClientId            string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectUri         string
	Scope               []string
}

func generateOAuthAuthorizationUrl(params OAuthAuthorizationParams) string {
	const baseUrl string = "https://accounts.google.com/o/oauth2/v2/auth"

	u, err := url.Parse(baseUrl)
	if err != nil {
		panic(err)
	}

	values := url.Values{}
	values.Add("client_id", params.ClientId)
	values.Add("code_challenge", params.CodeChallenge)
	values.Add("code_challenge_method", params.CodeChallengeMethod)
	values.Add("redirect_uri", params.RedirectUri)
	values.Add("response_type", "code")

	scope := ""

	for _, s := range params.Scope {
		scope += s + " "
	}

	values.Add("scope", scope)

	u.RawQuery = values.Encode()

	return u.String()
}

type OAuthTokenParams struct {
	ClientId     string
	ClientSecret string
	Code         string
	Verifier     string
	RedirectUri  string
}

func getOAuthAccessToken(params OAuthTokenParams) string {
	const baseUrl string = "https://oauth2.googleapis.com/token"

	client := &http.Client{
		Timeout: time.Minute,
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", params.ClientId)
	data.Set("client_secret", params.ClientSecret)
	data.Set("code_verifier", params.Verifier)
	data.Set("code", params.Code)
	data.Set("redirect_uri", params.RedirectUri)
	encodedData := data.Encode()

	req, err := http.NewRequest("POST", baseUrl, strings.NewReader(encodedData))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(encodedData)))

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		panic(err)
	}

	return body["access_token"].(string)
}

func listenOAuthRedirectUrlCode() (int, chan (string)) {
	code := make(chan (string))

	port := listenOAuthRedirectUrl(func(w http.ResponseWriter, r *http.Request) {
		code <- r.URL.Query().Get("code")
	})

	return port, code
}

func listenOAuthRedirectUrl(callback func(w http.ResponseWriter, r *http.Request)) int {
	server := &http.Server{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		callback(w, r)
		server.Shutdown(context.Background())
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}
