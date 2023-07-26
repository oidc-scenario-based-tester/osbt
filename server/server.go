package server

import (
	"sync"

	"github.com/gin-gonic/gin"
)

// TestResult represents a test result received from POST /result/add
type TestResult struct {
	TestName       string `json:"test_name"`
	Outcome        string `json:"outcome"`
	ErrMsg         string `json:"err_msg"`
	Countermeasure string `json:"countermeasure"`
}

var (
	// results stores all test results received
	results []TestResult
	// mutex is used to ensure that appending to results is thread-safe
	mutex = &sync.Mutex{}
)

func StartServer() {
	r := gin.Default()

	r.POST("/result/add", func(c *gin.Context) {
		var result TestResult
		if err := c.ShouldBindJSON(&result); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Append the test result to the results slice in a thread-safe manner
		mutex.Lock()
		results = append(results, result)
		mutex.Unlock()

		c.JSON(200, gin.H{"message": "Test result received successfully"})
	})

	r.GET("/results", func(c *gin.Context) {
		// Return all test results
		c.JSON(200, results)
	})

	r.Run(":54454") // listen and serve on specified port
}
