/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/opentdf/backend-go/pkg/tdf3"
	tdfClient "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Cmd represents the generate command
var tdfCmd = &cobra.Command{
	Use:   "tdf",
	Short: "Create a TDF",
	Run:   tdfTDF,
}

func init() {
	createCmd.AddCommand(tdfCmd)

	tdfCmd.Flags().String("file", "", "File to wrap with TDF")
	tdfCmd.Flags().String("text", "", "Text to wrap with TDF")
	tdfCmd.Flags().String("output", "file://test.tdf", "Output file")
	tdfCmd.Flags().Int("keysize", 256, "Key size")
	tdfCmd.Flags().StringArray("attribute", []string{}, "Attribute to apply to the TDF")
	tdfCmd.Flags().String("keySplitType", "split", "Key split type can be split or shamir")
	tdfCmd.Flags().String("encryptedMetatData", "", "Encrypted metadata")
}

func tdfTDF(cmd *cobra.Command, args []string) {
	var (
		reader io.Reader
		output string
	)

	if err := loadViperConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	text, err := cmd.Flags().GetString("text")
	if err != nil {
		log.Fatal(err)
	}

	o, err := cmd.Flags().GetString("output")
	if err != nil {
		log.Fatal(err)
	}

	attributes, err := cmd.Flags().GetStringArray("attribute")
	if err != nil {
		log.Fatal(err)
	}

	keySplitType, err := cmd.Flags().GetString("keySplitType")
	if err != nil {
		log.Fatal(err)
	}

	encryptedMetatData, err := cmd.Flags().GetString("encryptedMetatData")
	if err != nil {
		log.Fatal(err)
	}

	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		log.Fatal(err)
	}

	if !strings.HasPrefix(o, "file://") && !strings.HasPrefix(o, "https://") {
		log.Fatal("Output must be either file:// or https://")
	}

	if strings.HasPrefix(o, "file://") {
		output = strings.TrimPrefix(o, "file://")
	}

	if strings.HasPrefix(o, "https://") {
		output = strings.TrimPrefix(o, "https://")
	}

	if file == "" && text == "" {
		log.Fatal("Must specify either --file or --text")
	}

	if file != "" && text != "" {
		log.Fatal("Must specify either --file or --text, not both")
	}

	if file != "" {
		reader, err = os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer reader.(*os.File).Close()
	}

	if text != "" {
		reader = bytes.NewBufferString(text)
	}

	kasEndpoint := viper.GetStringSlice(fmt.Sprintf("profiles.%s.kasendpoint", profile))

	client, err := tdfClient.NewTDFClient(tdfClient.TDFClientOptions{
		KasEndpoint: kasEndpoint,
	})
	if err != nil {
		log.Fatal(err)
	}

	var parsedAttributes = []tdf3.Attribute{}
	for _, attr := range attributes {
		var parsedAttr tdf3.Attribute
		if err := parsedAttr.ParseAttributeFromString(attr); err != nil {
			log.Fatal(err)
		}
		parsedAttributes = append(parsedAttributes, parsedAttr)
	}

	outFile, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	start := time.Now()
	if err = client.Create(reader, outFile, &tdfClient.TDFCreateOptions{
		Attributes:        parsedAttributes,
		EncryptedMetadata: []byte(encryptedMetatData),
		KeySplitType:      keySplitType,
	}); err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("TDF created in %s\n", duration)
	fmt.Println("TDF created successfully")
}
