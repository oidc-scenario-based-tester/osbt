package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/example/server/exampleop"
	"github.com/zitadel/oidc/v2/example/server/storage"
)

type Task struct {
	Name string
	Args map[string]string
}

var tasks = make(map[string]Task)
var lock sync.RWMutex

func main() {
	port := "9997"
	issuer := fmt.Sprintf("http://localhost:%s/", port)

	userStore := storage.NewUserStore(issuer)
	storage := storage.NewStorage(userStore)

	opHandler := exampleop.SetupServer(issuer, storage)

	router := mux.NewRouter()
	// Add the task routes.
	router.HandleFunc("/task/{id}", getTask).Methods("GET")
	router.HandleFunc("/task", addTask).Methods("POST")
	router.HandleFunc("/task", deleteTasks).Methods("DELETE")

	router.PathPrefix("/").Handler(opHandler)

	// Add the task middleware.
	router.Use(requestMiddleware, responseMiddleware)

	server := &http.Server{
		Addr:    "localhost:" + port,
		Handler: router,
	}
	log.Printf("server listening on http://localhost:%s/", port)
	log.Println("press ctrl+c to stop")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func getTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	lock.RLock()
	defer lock.RUnlock()

	task, exists := tasks[id]
	if exists {
		json.NewEncoder(w).Encode(task)
	} else {
		http.Error(w, "Task not found", http.StatusNotFound)
	}
}

func addTask(w http.ResponseWriter, r *http.Request) {
	var t Task
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("task name: %s", t.Name)
	log.Printf("task args: %v", t.Args)

	lock.Lock()
	defer lock.Unlock()

	taskID := uuid.New().String()
	task := Task{
		Name: t.Name,
		Args: t.Args,
	}
	tasks[taskID] = task

	json.NewEncoder(w).Encode(map[string]string{"taskId": taskID})
}

func deleteTasks(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	tasks = make(map[string]Task)

	json.NewEncoder(w).Encode(map[string]string{"message": "Tasks deleted"})
}

func requestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = ioutil.ReadAll(r.Body)
		}

		// Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		// Use the content
		bodyString := string(bodyBytes)
		log.Printf("Request Body: %s", bodyString)

		log.Printf("Before middleware: Method - %s, Path - %s, Query Params - %v, Request Body - %s\n", r.Method, r.URL.Path, r.URL.Query(), bodyString)

		for _, task := range tasks {
			log.Printf("task name: %s", task.Name)
			log.Printf("task args: %v", task.Args)

			if task.Name == "IdPConfusion" {
				if r.Method == "GET" && r.URL.Path == "/auth" {
					log.Printf("IdPConfusion task")
					if honestIdpAuthEndpoint, ok := task.Args["honest_idp_auth_endpoint"]; ok {
						parsedUrl, err := url.Parse(honestIdpAuthEndpoint)
						if err != nil {
							log.Printf("Could not parse URL: %v", err)
							return
						}
						parsedUrl.RawQuery = r.URL.RawQuery
						http.Redirect(w, r, parsedUrl.String(), http.StatusFound)
						return // early return after redirect
					}
				}
			}
		}

		log.Printf("After middleware: Method - %s, Path - %s, Query Params - %v, Request Body - %s\n", r.Method, r.URL.Path, r.URL.Query(), bodyString)

		next.ServeHTTP(w, r)
	})
}

func responseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := NewResponseWriterInterceptor(w)
		next.ServeHTTP(rw, r)

		// Print out method, path, and body before middleware operations
		var body []byte
		if r.Body != nil {
			body, _ = ioutil.ReadAll(r.Body)
		}
		log.Printf("Before middleware: Method - %s, Path - %s, Query Params - %v, Request Body - %s, Response Body - %s\n", r.Method, r.URL.Path, r.URL.Query(), string(body), rw.Body)

		// assuming we always want to handle the first added task
		for _, task := range tasks {
			log.Printf("task name: %s", task.Name)
			log.Printf("task args: %v", task.Args)
			if task.Name == "IDSpoofing" {
				if r.Method == "POST" && r.URL.Path == "/oauth/token" {
					log.Printf("IDSpoofing task")
					// Parse the JSON body
					var body map[string]interface{}
					if err := json.Unmarshal(rw.Body, &body); err != nil {
						log.Printf("Could not parse JSON body: %v", err)
						return
					}

					// Replace the ID token
					if idToken, ok := task.Args["id_token"]; ok {
						body["id_token"] = idToken
						newBody, err := json.Marshal(body)
						if err != nil {
							log.Printf("Could not marshal JSON body: %v", err)
							return
						}

						// Replace the body in the ResponseWriterInterceptor
						rw.Body = newBody
					}
				}
			}

			if task.Name == "MaliciousEndpoint" {
				if r.Method == "GET" && r.URL.Path == "/.well-known/openid-configuration" {
					log.Printf("MaliciousEndpoint task")
					// Parse the JSON body
					var body map[string]interface{}
					if err := json.Unmarshal(rw.Body, &body); err != nil {
						log.Printf("Could not parse JSON body: %v", err)
						return
					}

					keys := []string{"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "registration_endpoint"}
					for key, value := range task.Args {
						for _, k := range keys {
							if key == k {
								body[key] = value
								break
							}
						}
					}

					newBody, err := json.Marshal(body)
					if err != nil {
						log.Printf("Could not marshal JSON body: %v", err)
						return
					}

					// Replace the body in the ResponseWriterInterceptor
					rw.Body = newBody
				}
			}
		}
		// Print out method, path, and body after middleware operations
		log.Printf("After middleware: Method - %s, Path - %s, Query Params - %v, Request Body - %s, Response Body - %s\n", r.Method, r.URL.Path, r.URL.Query(), string(body), rw.Body)
		rw.WriteToResponse()
	})
}

type ResponseWriterInterceptor struct {
	http.ResponseWriter
	Body        []byte
	wroteHeader bool
}

func NewResponseWriterInterceptor(w http.ResponseWriter) *ResponseWriterInterceptor {
	return &ResponseWriterInterceptor{
		ResponseWriter: w,
		Body:           []byte{},
	}
}

func (rw *ResponseWriterInterceptor) Write(b []byte) (int, error) {
	rw.Body = append(rw.Body, b...)
	return len(b), nil
}

func (rw *ResponseWriterInterceptor) WriteToResponse() {
	rw.ResponseWriter.Write(rw.Body)
}
