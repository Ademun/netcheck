/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"slices"

	"github.com/ademun/netcheck/network"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "netcheck",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 || args[0] == "" {
			fmt.Println("please provide an ip or domain name")
			os.Exit(1)
		}
		ip := args[0]

		ports, err := cmd.Flags().GetString("ports")
		if err != nil {
			fmt.Println(err)
		}
		if ports == "" {
			ports = "-"
		}
		v, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			fmt.Println(err)
		}

		fmt.Printf("Scanning %s ports on %s target\n", ports, ip)
		scanResult := network.ScanHost(ip, network.SplitPorts(ports))
		slices.SortFunc(scanResult, func(a network.Result, b network.Result) int {
			p1, p2 := network.ConvPort(a.Port), network.ConvPort(b.Port)
			return p1 - p2
		})
		fmt.Println("PORT\tSTATE")
		for _, r := range scanResult {
			if !v && r.Status == network.CLOSED {
				continue
			}
			fmt.Printf("%s\t%s\n", r.Port, r.Status)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("ports", "p", "", "Ports to scan")
	rootCmd.Flags().BoolP("verbose", "v", false, "Lists closed ports")
}
