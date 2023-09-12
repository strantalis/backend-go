/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/opentdf/backend-go/internal/auth"
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

	loginCmd.Flags().String("type", "", "client-credentials")
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
		conf := &auth.ClientCredentials{
			Config: &clientcredentials.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				TokenURL:     "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
			},
			PublicKey: popKeys.PublicKey,
		}
		tokens, err = conf.Login()
		if err != nil {
			log.Fatal(err)
		}
	default:
		conf := &auth.AuthorizaionCodePKCE{
			Oauth2Config: &oauth2.Config{
				ClientID:    clientID, //"52HgtF4HBt4I1SOyJNEhvF3Vwpw7F8VP",
				Scopes:      []string{"openid", "profile", "email"},
				RedirectURL: "http://localhost:3000/callback", //"http://localhost:8081/callback",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/auth",  //"https://dev-yzqjwcakzru3kxes.us.auth0.com/authorize",
					TokenURL: "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
				},
			},
			PublicKey: popKeys.PublicKey,
		}
		tokens, err = conf.Login()
		if err != nil {
			log.Fatal(err)
		}
	}
	creds.PoP = popKeys
	creds.Tokens = tokens
	jsonCreds, err := json.Marshal(creds)
	if err != nil {
		log.Fatal(err)
	}
	os.WriteFile("creds.json", jsonCreds, 0644)
}
