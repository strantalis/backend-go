/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/opentdf/backend-go/internal/auth"
	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// contentCmd represents the content command
var contentCmd = &cobra.Command{
	Use:   "content",
	Short: "Get the content of a TDF",
	Run:   content,
}

func init() {
	rootCmd.AddCommand(contentCmd)

	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	viper.AddConfigPath(fmt.Sprintf("%s/.opentdf", homedir))
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	contentCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")
	contentCmd.Flags().String("output", "stdout", "Where to write the decrypted payload file or stdout")
	contentCmd.Flags().String("output-file", "", "Output file to write decrypted content to")

}

func content(cmd *cobra.Command, args []string) {
	var (
		opentdfCredentials OpenTDFCredentials
		oauth2Client       *http.Client
	)
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		log.Fatal(err)
	}

	outputFile, err := cmd.Flags().GetString("output-file")
	if err != nil {
		log.Fatal(err)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	byteCredentials, err := os.ReadFile(fmt.Sprintf("%s/.opentdf/credentials.toml", homedir))
	if err != nil {
		log.Fatal(err)
	}
	if err = toml.Unmarshal(byteCredentials, &opentdfCredentials); err != nil {
		log.Fatal(err)
	}

	oidcEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcendpoint", opentdfCredentials.Profile))
	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", opentdfCredentials.Profile))
	clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", opentdfCredentials.Profile))

	if clientSecret != "" {
		conf := auth.ClientCredentials{
			Config: &clientcredentials.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				TokenURL:     fmt.Sprintf("%s/openid-connect/token", oidcEndpoint), //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
			},
			PublicKey: opentdfCredentials.PublicKey,
		}

		oauth2Client, err = conf.Client()
		if err != nil {
			log.Fatal(err)
		}

	} else {
		ts := &auth.OpenTdfTokenSource{
			OpenTdfToken: opentdfCredentials.Tokens,
		}
		oauth2Client = oauth2.NewClient(context.Background(), ts)
	}
	kasEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.kasendpoint", opentdfCredentials.Profile))

	client, err := tdf3.NewTDFClient(tdf3.TDFClientOptions{
		KasEndpoint: kasEndpoint,
		HttpClient:  oauth2Client,
		PrivKey:     opentdfCredentials.PrivateKey,
		PubKey:      opentdfCredentials.PublicKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	tdf, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}

	var w io.Writer
	switch output {
	case "stdout":
		w = os.Stdout
	case "file":
		w, err = os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer w.(*os.File).Close()
	err = client.GetContent(tdf, w)
	if err != nil {
		log.Fatal(err)
	}
}
