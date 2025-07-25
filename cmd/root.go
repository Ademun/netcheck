/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ademun/netcheck/network"
	"github.com/ademun/netcheck/reports"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "netcheck",
	Short: "A minimalist TCP port scanner with parallel scanning and range support",
	Long: `netcheck performs fast TCP port scanning. Key features:
• Parallel scanning with configurable concurrency
• Flexible port specification (80,443,1000-2000)

Examples:
  Scan web ports: netcheck -p 80,443,8080 example.com
  Scan range:     netcheck -p 22-100 example.com
  Full scan:      netcheck example.com -v

Use only on networks you own or have explicit permission to scan!`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 || args[0] == "" {
			fmt.Println("please provide an ip or domain name")
			os.Exit(1)
		}

		ports, err := cmd.Flags().GetString("ports")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		v, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		out, err := cmd.Flags().GetString("output")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ip := args[0]
		if ports == "" {
			ports = "-"
		}

		start := time.Now()

		scanResults := network.ScanHost(ip, network.SplitPorts(ports))
		slices.SortFunc(scanResults, func(a network.Result, b network.Result) int {
			p1, p2 := network.ConvPort(a.Port), network.ConvPort(b.Port)
			return p1 - p2
		})

		end := time.Now()
		print(scanResults, v)
		manageReport(out, ip, scanResults, start, end)
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
	rootCmd.Flags().StringP("output", "o", "", "Saves report to file: json | csv")
}

func print(results []network.Result, verbose bool) {
	slices.SortFunc(results, func(a, b network.Result) int {
		return network.ConvPort(a.Port) - network.ConvPort(b.Port)
	})

	fmt.Println("\n" + strings.Repeat("═", 30))
	fmt.Printf("NETCHECK SCAN REPORT (scanned %d port(s))\n", len(results))
	fmt.Println(strings.Repeat("═", 30))

	printResults(results, verbose)
	fmt.Println("\n" + strings.Repeat("═", 30))
}

func printResults(results []network.Result, verbose bool) {
	fmt.Println("PORT\tSTATE\tSERVICE")

	for _, r := range results {
		if !verbose && r.Status == network.CLOSED {
			continue
		}
		port := fmt.Sprintf("%-5s", r.Port)
		status := fmt.Sprintf("%-7s", r.Status)
		fmt.Printf("%s\t%s\t%s\n", port, status, r.Banners)
	}
}

func manageReport(output string, target string, results []network.Result, start time.Time, end time.Time) {
	metadata := &reports.Metadata{Target: target, StartTime: start, EndTime: end, Total: end.Sub(start).String(), Scanner: "netcheck 1.0"}
	report := &reports.Report{Metadata: metadata, Results: results}
	switch output {
	case "json":
		path, err := report.SaveJSON()
		if err != nil {
			fmt.Println("JSON export failed:", err)
			os.Exit(1)
		}
		fmt.Println("JSON report saved to", path)

	case "csv":
		path, err := report.SaveCSV()
		if err != nil {
			fmt.Println("CSV export failed:", err)
			os.Exit(1)
		}
		fmt.Println("CSV report saved to", path)

	}
}
