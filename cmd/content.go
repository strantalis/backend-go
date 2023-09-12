/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/opentdf/backend-go/internal/auth"
	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// contentCmd represents the content command
var contentCmd = &cobra.Command{
	Use:   "content",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: content,
}

func init() {
	rootCmd.AddCommand(contentCmd)

	viper.AddConfigPath("$HOME/.opentdf")
	viper.SetConfigName("config")
	viper.SetConfigType("toml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	contentCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")

}

func content(cmd *cobra.Command, args []string) {
	var (
		opentdfConfig      OpenTDFConfig
		opentdfCredentials OpenTDFCredentials
		oauth2Client       *http.Client
	)
	file, err := cmd.Flags().GetString("file")
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

	if err = viper.Unmarshal(&opentdfConfig); err != nil {
		log.Fatal(err)
	}

	if opentdfConfig.ClientSecret != "" {

		conf := auth.ClientCredentials{
			Config: &clientcredentials.Config{
				ClientID:     opentdfConfig.ClientID,
				ClientSecret: opentdfConfig.ClientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				TokenURL:     fmt.Sprintf("%s/openid-connect/token", opentdfConfig.OidcEndpoint), //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
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

	client, err := tdf3.NewTDFClient(tdf3.TDFClientOptions{
		KasEndpoint: "https://platform.virtru.us/api/kas",
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
	content, err := client.GetContent(tdf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted Content: ", string(content))
}
