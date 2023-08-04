package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/oidc-scenario-based-tester/osbt/server"
	"github.com/spf13/cobra"
)

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
	runCmd.Flags().StringP("timeout", "t", "30s", "Specify the timeout for running tests")

	rootCmd.AddCommand(runCmd, serverCmd)
	rootCmd.Execute()
}

func runTests(cmd *cobra.Command, args []string) {
	file, _ := cmd.Flags().GetString("file")
	dir, _ := cmd.Flags().GetString("dir")
	recursive, _ := cmd.Flags().GetBool("recursive")
	timeout, _ := cmd.Flags().GetString("timeout")

	timeoutDuration, err := time.ParseDuration(timeout)
	if err != nil {
		fmt.Printf("Invalid timeout value: %v", err)
		os.Exit(1)
	}

	if file != "" {
		runTest(file, timeoutDuration)
	}

	if dir != "" {
		runTestsInDir(dir, recursive, timeoutDuration)
	}
}

func runTest(file string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python", file)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Printf("Timeout running test: %s\n", file)
		} else {
			fmt.Printf("Error running test: %v\n", err)
		}
	} else {
		fmt.Printf("Test result: %s\n", out.String())
	}
}

func runTestsInDir(dir string, recursive bool, timeout time.Duration) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".py" {
			runTest(path, timeout)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error running tests in directory: %v\n", err)
	}
}
