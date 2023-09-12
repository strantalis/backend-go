/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/opentdf/backend-go/internal/auth"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type OpenTDFCredentials struct {
	Tokens     *oauth2.Token `toml:"tokens"`
	PrivateKey []byte        `toml:"privateKey"`
	PublicKey  []byte        `toml:"publicKey"`
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your OpenTDF Environment",
	Run:   login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	viper.AddConfigPath("$HOME/.opentdf")
	viper.SetConfigName("config")
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	loginCmd.Flags().String("client-id", "", "Client ID")
	loginCmd.Flags().String("client-secret", "", "Client Secret")
	loginCmd.Flags().String("oidc-endpoint", "", "OIDC Endpoint")
	loginCmd.Flags().String("profile", "default", "Profile to use")

	viper.BindPFlag("clientid", loginCmd.Flags().Lookup("client-id"))
	viper.BindPFlag("clientsecret", loginCmd.Flags().Lookup("client-secret"))
	viper.BindPFlag("oidcendpoint", loginCmd.Flags().Lookup("oidc-endpoint"))

}

func login(cmd *cobra.Command, args []string) {
	var (
		tokens             *oauth2.Token
		err                error
		opentdfCredentials OpenTDFCredentials
	)

	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		log.Fatal(err)
	}

	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", profile))
	oidcEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcendpoint", profile))

	opentdfCredentials.PrivateKey, opentdfCredentials.PublicKey, err = tdfCrypto.GenerateRSAKeysPem(2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v\n", err)
	}

	if clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", profile)); clientSecret != "" {

		conf := &auth.ClientCredentials{
			Config: &clientcredentials.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				TokenURL:     fmt.Sprintf("%s/openid-connect/token", oidcEndpoint), //"https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
			},
			PublicKey: opentdfCredentials.PublicKey,
		}
		tokens, err = conf.Login()
		if err != nil {
			log.Fatal(err)
		}
		opentdfCredentials.Tokens = tokens
	} else {
		conf := &auth.AuthorizaionCodePKCE{
			Oauth2Config: &oauth2.Config{
				ClientID:    clientID, //"52HgtF4HBt4I1SOyJNEhvF3Vwpw7F8VP",
				Scopes:      []string{"openid", "profile", "email"},
				RedirectURL: "http://localhost:3000/callback", //"http://localhost:8081/callback",
				Endpoint: oauth2.Endpoint{
					AuthURL:  fmt.Sprintf("%s/openid-connect/auth", oidcEndpoint),  //"https://dev-yzqjwcakzru3kxes.us.auth0.com/authorize",
					TokenURL: fmt.Sprintf("%s/openid-connect/token", oidcEndpoint), //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
				},
			},
			PublicKey: opentdfCredentials.PublicKey,
		}
		tokens, err = conf.Login()
		if err != nil {
			log.Fatal(err)
		}
		opentdfCredentials.Tokens = tokens
	}

	tomlCreds, err := toml.Marshal(opentdfCredentials)
	if err != nil {
		log.Fatal(err)
	}
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	os.WriteFile(fmt.Sprintf("%s/.opentdf/credentials.toml", homedir), tomlCreds, 0644)
}
