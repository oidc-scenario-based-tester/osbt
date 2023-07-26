package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/oidc-scenario-based-tester/osbt/server"
	"github.com/spf13/cobra"
)

const resultsFile = "osbt.log"

func main() {
	var rootCmd = &cobra.Command{Use: "osbt"}
	var runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the tests",
		Run:   runTests,
	}
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the server that receives and saves the test results",
		Run: func(cmd *cobra.Command, args []string) {
			server.StartServer()
		},
	}

	runCmd.Flags().StringP("file", "f", "", "Specify the test file to run")
	runCmd.Flags().StringP("dir", "d", "", "Specify the test directory to run all tests")
	runCmd.Flags().BoolP("recursive", "r", false, "Search directories recursively")
	runCmd.Flags().StringP("output", "o", "", "Specify the output file to store the test results")

	rootCmd.AddCommand(runCmd, serverCmd)
	rootCmd.Execute()
}

func runTests(cmd *cobra.Command, args []string) {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	recursive, _ := cmd.Flags().GetBool("recursive")
	output, _ := cmd.Flags().GetString("output")

	if file != "" {
		result, _ := runTest(file)
		saveResults(resultsFile, result)
		if output != "" {
			saveResults(output, result)
		}
	}

	if dir != "" {
		runTestsInDir(dir, recursive, output)
	}
}

func runTest(file string) (string, error) {
	cmd := exec.Command("python", file)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func runTestsInDir(dir string, recursive bool, output string) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".py" {
			result, _ := runTest(path)
			saveResults(resultsFile, result)
			if output != "" {
				saveResults(output, result)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println("Error running tests:", err)
	}
}

func saveResults(file string, result string) {
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()
	f.WriteString(result)
	f.WriteString("\n")
}
