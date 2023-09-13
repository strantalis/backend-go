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

	"github.com/opentdf/backend-go/pkg/tdf3"
	"github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: generateTDF,
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().String("file", "", "File to wrap with TDF")
	generateCmd.Flags().String("text", "", "Text to wrap with TDF")
	generateCmd.Flags().String("output", "file://test.tdf", "Output file")
	generateCmd.Flags().Int("keysize", 256, "Key size")
	generateCmd.Flags().StringArray("attribute", []string{}, "Attribute to apply to the TDF")
}

func generateTDF(cmd *cobra.Command, args []string) {
	var reader io.Reader
	var output string

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

	keySize, err := cmd.Flags().GetInt("keysize")
	if err != nil {
		log.Fatal(err)
	}

	attributes, err := cmd.Flags().GetStringArray("attribute")
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

	client, err := client.NewTDFClient(client.TDFClientOptions{KeyLength: &keySize, KasEndpoint: "https://platform.virtru.us/api/kas"})
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

	var out []byte
	if out, err = client.Create(reader, parsedAttributes); err != nil {
		log.Fatal(err)
	}

	outFile, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()
	if _, err := outFile.Write(out); err != nil {
		log.Fatal(err)
	}
	fmt.Println("TDF generated")
}
