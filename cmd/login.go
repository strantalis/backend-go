/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().String("type", "authorization-code", "client-credentials or authorization-code")
	loginCmd.Flags().String("client-id", "", "Client ID")
	loginCmd.Flags().String("client-secret", "", "Client Secret")
}

type Credentials struct {
	Tokens *oauth2.Token `json:"tokens"`
	PoP    *PoP          `json:"pop"`
}

type PoP struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
}

var (
	creds   = new(Credentials)
	popKeys = new(PoP)
)

func login(cmd *cobra.Command, args []string) {
	var (
		tokens *oauth2.Token
	)
	loginType, err := cmd.Flags().GetString("type")
	if err != nil {
		log.Fatal(err)
	}
	clientID, err := cmd.Flags().GetString("client-id")
	if err != nil {
		log.Fatal(err)
	}

	popKeys.PrivateKey, popKeys.PublicKey, err = tdfCrypto.GenerateRSAKeysPem(2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v\n", err)
	}

	switch loginType {
	case "client-credentials":
		clientSecret, err := cmd.Flags().GetString("client-secret")
		if err != nil {
			log.Fatal(err)
		}
		tokens, err = clientCredentialFlow(clientID, clientSecret)
		if err != nil {
			log.Fatal(err)
		}
	case "authorization-code":
		tokens, err = authorizationCodeFlow(clientID)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Invalid login type")
	}
	creds.PoP = popKeys
	creds.Tokens = tokens
	jsonCreds, err := json.Marshal(creds)
	if err != nil {
		log.Fatal(err)
	}
	os.WriteFile("creds.json", jsonCreds, 0644)
}

func generateCodeVerifier() (string, error) {
	const codeVerifierLength = 32 // You can adjust the length of the code verifier as needed
	randomBytes := make([]byte, codeVerifierLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func authorizationCodeFlow(clientID string) (*oauth2.Token, error) {
	var (
		tokens *oauth2.Token
	)
	// Configure the OAuth2 client.
	conf := &oauth2.Config{
		ClientID:    clientID, //"52HgtF4HBt4I1SOyJNEhvF3Vwpw7F8VP",
		Scopes:      []string{"openid", "profile", "email"},
		RedirectURL: "http://localhost:3000/callback", //"http://localhost:8081/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/auth",  //"https://dev-yzqjwcakzru3kxes.us.auth0.com/authorize",
			TokenURL: "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
		},
	}

	// Create a HTTP server to handle the callback from Keycloak.":8081"
	srv := &http.Server{Addr: ":3000"}
	stop := make(chan os.Signal, 1)

	// Generate a code verifier and code challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %v", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Start a web server to handle the OAuth2 callback.
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Get the authorization code from the query parameters.
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		// Exchange the authorization code for an access token.
		token, err := conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange authorization code: %v", err), http.StatusInternalServerError)
			return
		}

		// Build PoP Request with refresh token to get tdf_claims in jwt
		formBody := bytes.NewBufferString(fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", token.RefreshToken, clientID))
		req, err := http.NewRequest(http.MethodPost, "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", formBody)
		fmt.Println(req.URL.String())
		req.Header.Set("X-VirtruPubKey", base64.StdEncoding.EncodeToString(popKeys.PublicKey))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Error getting token: %v\n", err)
		}
		err = json.NewDecoder(resp.Body).Decode(&tokens)
		if err != nil {
			log.Fatalf("Error decoding token: %v\n", err)
		}
		// Write the user info to the response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("Return to the CLI to continue.")
		fmt.Println("Shutting down HTTP server...")

		// Send a value to the stop channel to simulate the SIGINT signal.
		stop <- syscall.SIGINT
	})
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"), oauth2.SetAuthURLParam("audience", "https://dev-yzqjwcakzru3kxes.us.auth0.com/api/v2/"))
	fmt.Println(url)
	openBrowser(url)

	// Start the HTTP server in a separate goroutine.
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for a SIGINT or SIGTERM signal to shutdown the server.
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down HTTP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Failed to shutdown HTTP server gracefully: %v", err)
		return tokens, err
	}
	return tokens, nil
}

func openBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		return fmt.Errorf("failed to open browser: %v", err)
	}

	return nil
}

func clientCredentialFlow(clientID string, clientSecret string) (*oauth2.Token, error) {

	conf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		TokenURL:     "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
	}

	hc := &http.Client{Transport: &clientCredientialFlowCustomTransport{}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, hc)

	tokens, err := conf.Token(ctx)
	if err != nil {
		return nil, err
	}
	return tokens, nil

}

type clientCredientialFlowCustomTransport struct{}

func (t *clientCredientialFlowCustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	// Set X-VirtruPubKey header
	req.Header.Set("X-VirtruPubKey", base64.StdEncoding.EncodeToString(popKeys.PublicKey))

	// Call default rounttrip
	response, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// return result of default roundtrip
	return response, err
}
