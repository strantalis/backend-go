/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/opentdf/backend-go/internal/auth"
	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// contentCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// contentCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	contentCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")
	contentCmd.Flags().String("key", "", "Key to decrypt payload")

	// contentCmd.MarkFlagRequired("key")

}

func content(cmd *cobra.Command, args []string) {
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	// Will use this for split key
	// key, err := cmd.Flags().GetString("key")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	bcreds, err := os.ReadFile("creds.json")
	if err != nil {
		log.Fatal(err)
	}
	creds := new(Credentials)
	err = json.Unmarshal(bcreds, &creds)
	if err != nil {
		log.Fatal(err)
	}

	conf := auth.ClientCredentials{
		Config: &clientcredentials.Config{
			ClientID:     "tdf-client",
			ClientSecret: "123-456",
			Scopes:       []string{"openid", "profile", "email"},
			TokenURL:     "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
		},
		PublicKey: creds.PoP.PublicKey,
	}

	oauth2Client, err := conf.Client()
	if err != nil {
		log.Fatal(err)
	}
	client, err := tdf3.NewTDFClient(tdf3.TDFClientOptions{
		KasEndpoint: "https://platform.virtru.us/api/kas",
		HttpClient:  oauth2Client,
		PrivKey:     creds.PoP.PrivateKey,
		PubKey:      creds.PoP.PublicKey,
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
