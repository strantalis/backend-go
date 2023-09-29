/*
Copyright © 2023 OpenTDF opentdf@virtru.com
*/
package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/spf13/cobra"
)

// Profiling Parameters
var (
	cpuProfile     bool
	memProfile     bool
	cpuProfileFile string
	memProfileFile string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "opentdf",
	Short: "A brief description of your application",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		onStopProfiling = profilingInit()
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	defer stopProfiling()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.backend-go.yaml)")

	// Profile Config Flag
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.opentdf/config)")

	// Profiling cli flags
	rootCmd.PersistentFlags().BoolVar(&cpuProfile, "cpu-profile", false, "write cpu profile to file")
	rootCmd.PersistentFlags().BoolVar(&memProfile, "mem-profile", false, "write memory profile to file")

	rootCmd.PersistentFlags().StringVar(&cpuProfileFile, "cpu-profile-file", "cpu.prof", "write cpu profile to file")
	rootCmd.PersistentFlags().StringVar(&memProfileFile, "mem-profile-file", "mem.prof", "write memory profile to file")
}

// profilingInit starts cpu and memory profiling if enabled.
// It returns a function to stop profiling.
func profilingInit() func() {
	// doOnStop is a list of functions to be called on stop
	var doOnStop []func()
	// stop calls all necessary functions to stop profiling
	stop := func() {
		for _, d := range doOnStop {
			if d != nil {
				d()
			}
		}
	}

	if cpuProfile {
		fmt.Println("cpu profile enabled")

		// Create profiling file
		f, err := os.Create(cpuProfileFile)
		if err != nil {
			fmt.Println("could not create cpu profile file")
			return stop
		}

		// Start profiling
		err = pprof.StartCPUProfile(f)
		if err != nil {
			fmt.Println("could not start cpu profiling")
			return stop
		}

		// Add function to stop cpu profiling to doOnStop list
		doOnStop = append(doOnStop, func() {
			pprof.StopCPUProfile()
			_ = f.Close()
			fmt.Println("cpu profile stopped")
		})
	}

	if memProfile {
		fmt.Println("memory profile enabled")

		// Create profiling file
		f, err := os.Create(memProfileFile)
		if err != nil {
			fmt.Println("could not create memory profile file")
			return stop
		}

		// Add function to stop memory profiling to doOnStop list
		doOnStop = append(doOnStop, func() {
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
			fmt.Println("memory profile stopped")
		})
	}

	return stop
}

// onStopProfiling is called when the cli exits
// profilingOnce makes sure it's only called once
var onStopProfiling func()
var profilingOnce sync.Once

// stopProfiling triggers _stopProfiling.
// It's safe to be called multiple times.
func stopProfiling() {
	if onStopProfiling != nil {
		profilingOnce.Do(onStopProfiling)
	}
}
