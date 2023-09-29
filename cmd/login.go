/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/pkg/oidc"
	"golang.org/x/oauth2"
)

type Key []byte

func (k Key) MarshalYAML() (interface{}, error) {
	return base64.StdEncoding.EncodeToString(k), nil
}

func (k *Key) UnmarshalYAML(node *yaml.Node) error {
	value := node.Value
	ba, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	*k = ba
	return nil
}

type OpenTDFCredentials struct {
	Profile    string        `yaml:"profile"`
	Tokens     *oauth2.Token `yaml:"tokens"`
	PrivateKey Key           `yaml:"privateKey"`
	PublicKey  Key           `yaml:"publicKey"`
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your OpenTDF Environment",
	Run:   login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error getting user home directory: %v", homeDir)
	}

	loginCmd.Flags().String("client-id", "", "Client ID")
	loginCmd.Flags().String("client-secret", "", "Client Secret")
	loginCmd.Flags().String("credentials-file", fmt.Sprintf("%s/.opentdf/credentials", homeDir), "Location to store credentials for subsequent commands")
	loginCmd.Flags().String("oidc-endpoint", "", "OIDC Endpoint")
	loginCmd.Flags().String("profile", "default", "Profile to use")

}

func login(cmd *cobra.Command, args []string) {
	var (
		err                error
		opentdfCredentials OpenTDFCredentials
	)

	if err := loadViperConfig(); err != nil {
		fmt.Printf(
			`
%s

Please create a config file or run the following command:

$ opentdf configure

`, err.Error())
		os.Exit(1)
	}
	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		log.Fatal(err)
	}

	credentialsFile, err := cmd.Flags().GetString("credentials-file")
	if err != nil {
		fmt.Printf("could not get credentials-file flag value: %v", err)
		os.Exit(1)
	}

	viper.BindPFlag(fmt.Sprintf("profiles.%s.clientid", cmd.Flags().Lookup("profile")), cmd.Flags().Lookup("client-id"))
	viper.BindPFlag(fmt.Sprintf("profiles.%s.clientsecret", cmd.Flags().Lookup("profile")), cmd.Flags().Lookup("client-secret"))
	viper.BindPFlag(fmt.Sprintf("profiles.%s.oidcendpoint", cmd.Flags().Lookup("profile")), cmd.Flags().Lookup("oidc-endpoint"))

	opentdfCredentials.Profile = profile

	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", profile))
	clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", profile))
	oidcDiscoveryEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcdiscoveryendpoint", profile))

	// Generate new private/public key pair for future use.
	opentdfCredentials.PrivateKey, opentdfCredentials.PublicKey, err = tdfCrypto.GenerateRSAKeysPem(2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v\n", err)
	}

	oClient, err := oidc.NewOidcClient(oidc.OidcConfig{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		DiscoveryEndpoint: oidcDiscoveryEndpoint,
		PublicKey:         opentdfCredentials.PublicKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	opentdfCredentials.Tokens, err = oClient.Login()
	if err != nil {
		log.Fatal(err)
	}

	creds, err := yaml.Marshal(opentdfCredentials)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Writing credentials to: ", credentialsFile)
	if err := os.WriteFile(credentialsFile, creds, 0644); err != nil {
		fmt.Printf("error writing credential files: %v", err)
		os.Exit(1)
	}
}
