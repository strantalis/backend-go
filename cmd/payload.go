/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/opentdf/backend-go/pkg/oidc"
	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// contentCmd represents the content command
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Get the payload of a TDF",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := loadViperConfig(); err != nil {
			fmt.Printf(
				`
%s

Please create a config file or run the following command:

$ opentdf configure

`, err.Error())
			os.Exit(1)
		}
	},
	Run: payload,
}

func init() {
	getCmd.AddCommand(payloadCmd)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("error getting user home directory: %v", homeDir)
	}

	payloadCmd.Flags().String("credentials-file", fmt.Sprintf("%s/.opentdf/credentials", homeDir), "Location to read credentials from")
	payloadCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")
	payloadCmd.Flags().String("output", "stdout", "Where to write the decrypted payload file or stdout")
	payloadCmd.Flags().String("output-file", "", "Output file to write decrypted payload to")

}

func payload(cmd *cobra.Command, args []string) {
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

	credentialsFileLocation, err := cmd.Flags().GetString("credentials-file")
	if err != nil {
		fmt.Printf("could not get credentials-file flag value: %v", err)
		os.Exit(1)
	}

	credentialFile, err := os.ReadFile(credentialsFileLocation)
	if err != nil {
		log.Fatal(err)
	}
	if err = yaml.Unmarshal(credentialFile, &opentdfCredentials); err != nil {
		log.Fatal(err)
	}

	oidcDiscoveryEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcdiscoveryendpoint", opentdfCredentials.Profile))
	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", opentdfCredentials.Profile))
	clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", opentdfCredentials.Profile))
	oClient, err := oidc.NewOidcClient(oidc.OidcConfig{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		DiscoveryEndpoint: oidcDiscoveryEndpoint,
		PublicKey:         opentdfCredentials.PublicKey,
		Tokens:            opentdfCredentials.Tokens,
	})
	if err != nil {
		log.Fatal(err)
	}
	oauth2Client, err = oClient.Client()
	if err != nil {
		log.Fatal(err)
	}
	kasEndpoint := viper.GetStringSlice(fmt.Sprintf("profiles.%s.kasendpoint", opentdfCredentials.Profile))

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
	start := time.Now()
	size, err := tdf.Stat()
	if err != nil {
		log.Fatal(err)
	}
	err = client.GetPayload(tdf, size.Size(), w)
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("\nDecrypted TDF payload in %s\n", duration)
}
