/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/opentdf/backend-go/internal/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Profiles map[string]OpenTDFConfig `yaml:"profiles"`
}

type OpenTDFConfig struct {
	KasEndpoint           []string `yaml:"kasendpoint"`
	OidcDiscoveryEndpoint string   `yaml:"oidcdiscoveryendpoint"`
	ClientID              string   `yaml:"clientid"`
	ClientSecret          string   `yaml:"clientsecret,omitempty"`
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure the TDF CLI",
	Run: func(cmd *cobra.Command, args []string) {
		if err := loadViperConfig(); err != nil {
			fmt.Println("No config file found, continuing without config file")
		}

		p := tea.NewProgram(tui.InitialModel())
		m, err := p.Run()
		if err != nil {
			fmt.Printf("the tea is rotten: %v", err)
			os.Exit(1)
		}
		// Assert the final tea.Model to our local model and print the choice.
		if _, ok := m.(tui.Model); !ok {
			fmt.Print("can't assert tui model")
			os.Exit(1)
		}

		if m.(tui.Model).Quit {
			fmt.Println("Not saving configuration...")
			os.Exit(0)
		}

		otdfConfig := OpenTDFConfig{
			OidcDiscoveryEndpoint: m.(tui.Model).Inputs[tui.OidcDiscoveryEndpoint].Value(),
			ClientID:              m.(tui.Model).Inputs[tui.ClientID].Value(),
			KasEndpoint:           strings.Split(m.(tui.Model).Inputs[tui.KasEndpoint].Value(), ","),
		}
		if m.(tui.Model).Inputs[tui.ClientSecret].Value() != "" {
			otdfConfig.ClientSecret = m.(tui.Model).Inputs[tui.ClientSecret].Value()
		}
		profileName := m.(tui.Model).Inputs[tui.ProfileName].Value()
		if profileName == "" {
			profileName = "default"
		}
		config := Config{
			Profiles: map[string]OpenTDFConfig{
				profileName: otdfConfig,
			},
		}
		err = viper.Unmarshal(&config)
		if err != nil {
			fmt.Printf("could not load configuration into viper: %v", err)
			os.Exit(1)
		}
		yamlConfig, err := yaml.Marshal(&config)
		if err != nil {
			fmt.Printf("could not marshal configuration to []byte: %v", err)
			os.Exit(1)
		}
		yamlReader := bytes.NewReader(yamlConfig)
		err = viper.MergeConfig(yamlReader)
		if err != nil {
			fmt.Printf("could not merge existing configuration: %v", err)
			os.Exit(1)
		}

		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		if _, err := os.Stat(fmt.Sprintf("%s/.opentdf", homedir)); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(fmt.Sprintf("%s/.opentdf", homedir), os.ModePerm)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}

		if err := viper.WriteConfigAs(fmt.Sprintf("%s/.opentdf/config", homedir)); err != nil {
			fmt.Printf("viper could not save configuration: %v", err)
			os.Exit(1)
		}
		fmt.Println("Config saved! ", fmt.Sprintf("%s/.opentdf/config", homedir))
	},
}

func init() {
	rootCmd.AddCommand(configCmd)

}

func loadViperConfig() error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Can't read homedir:", err.Error())
		os.Exit(1)
	}
	viper.AddConfigPath(fmt.Sprintf("%s/.opentdf", homedir))
	viper.AddConfigPath(".opentdf")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	return nil
}
