package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	//"github.com/gomodule/redigo/redis"
	"github.com/go-redis/redis"
	"github.com/gofrs/uuid"
)

// Account sql structure
// CREATE TABLE users(
//		id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
//  	username VARCHAR(50),
// password VARCHAR(120)
// );

var db *sql.DB
var err error

// Redis
var cache redis.Conn

//var u1 = uuid.Must(uuid.New4())
// Template parse
var templates *template.Template

func main() {
	// default load template
	templates = template.Must(template.ParseGlob("app/views/layouts/*.gohtml"))
	// init radis
	initCache()

	// Load database
	// db, err = sql.Open("mysql", "myUsername:myPassword@/myDatabase")
	//db, err = sql.Open("mysql", "root:10184902125410@/golang_db")
	//if err != nil {
	//	panic(err.Error())
	//}
	//defer db.Close()

	//err = db.Ping()
	//if err != nil {
	//	panic(err.Error())
	//}

	//handler := http.NewServeMux()

	// C R U D
	//handler.HandleFunc("/", Logger(indexHandler))
	//handler.HandleFunc("/hello/", Logger(BasicAuth(helloHandler)))

	//handler.HandleFunc("/book/", Logger(bookHandler))

	//handler.HandleFunc("/books/", Logger(booksHandler))

	r := mux.NewRouter()
	// main deep router
	r.HandleFunc("/", Logger(indexHandler))

	// administrative router
	r.HandleFunc("/manage", Logger(indexManage))

	// register and login & refrach route
	r.HandleFunc("/signup", Logger(signupPage))
	r.HandleFunc("/login", Logger(loginPage))
	http.HandleFunc("/refresh", Refresh)

	// misc router
	r.HandleFunc("/hello/", Logger(BasicAuth(helloHandler)))
	r.HandleFunc("/book/", Logger(bookHandler))
	r.HandleFunc("/books/", Logger(booksHandler))

	http.Handle("/", r)

	// server configs
	s := http.Server{
		Addr: ":8000",
		//Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	// Test log server witch fatal error
	log.Fatal(s.ListenAndServe())
}

func initCache() {
	/*
		// Initialize the redis connection to a redis instance running on your local machine
		conn, err := redis.DialURL("localhost:6379")
		if err != nil {
			panic(err)
		}
		// Assign the connection to the package level `cache` variable
		cache = conn
	*/
}

type Resp struct {
	// resp structure
	Message interface{}
	Error   string
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	name := strings.Replace(r.URL.Path, "/hello/", "", 1)

	resp := Resp{
		Message: fmt.Sprintf("hello %s. Glad to see you again", name),
	}

	respJson, _ := json.Marshal(resp)

	w.WriteHeader(http.StatusOK)

	w.Write(respJson)
}

func Logger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		log.Printf("Server: [net/http] method [%s] connection from [%v]", r.Method, r.RemoteAddr)

		next.ServeHTTP(w, r)
	}
}

func bookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		handleGetBook(w, r)
	} else if r.Method == http.MethodPost {
		handleAddBook(w, r)
	} else if r.Method == http.MethodDelete {
		handleDeleteBook(w, r)
	} else if r.Method == http.MethodPut {
		handleUpdateBook(w, r)
	}
}

func BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(auth) != 2 || auth[0] != "Basic" {
			http.Error(w, "authorization failed", http.StatusUnauthorized)

			return
		}

		hashed, _ := base64.StdEncoding.DecodeString(auth[1])

		pair := strings.SplitN(string(hashed), ":", 2)

		log.Printf("pair %+v", pair)

		if len(pair) != 2 || !aAuth(pair[0], pair[1]) {
			http.Error(w, "Authorization failed!", http.StatusUnauthorized)

			return
		}
		next.ServeHTTP(w, r)
	}
}

func aAuth(username, password string) bool {
	if username == "test" && password == "test" {
		return true
	}
	return false
}

func handleUpdateBook(w http.ResponseWriter, r *http.Request) {
	id := strings.Replace(r.URL.Path, "/book/", "", 1)
	decoder := json.NewDecoder(r.Body)

	var book Book

	var resp Resp

	err := decoder.Decode(&book)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Error = err.Error()
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}

	book.Id = id

	err = bookStore.UpdateBook(book)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Error = fmt.Sprintf("")
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}
	resp.Message = book

	respJson, _ := json.Marshal(resp)
	w.WriteHeader(http.StatusOK)
	w.Write(respJson)
}

func handleDeleteBook(w http.ResponseWriter, r *http.Request) {
	id := strings.Replace(r.URL.Path, "/book/", "", 1)

	var resp Resp

	err := bookStore.DeleteBook(id)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Error = fmt.Sprintf("")
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}
	booksHandler(w, r)
}

func handleAddBook(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var book Book

	var resp Resp

	err := decoder.Decode(&book)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Error = err.Error()
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}

	err = bookStore.AddBooks(book)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp.Error = err.Error()
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}
	booksHandler(w, r)
}

func booksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		handleGetBook(w, r)
	}
	w.WriteHeader(http.StatusOK)
	resp := Resp{
		Message: bookStore.GetBooks(),
	}
	booksJson, _ := json.Marshal(resp)
	w.Write(booksJson)
}

func handleGetBook(w http.ResponseWriter, r *http.Request) {
	id := strings.Replace(r.URL.Path, "/book/", "", 1)

	var resp Resp

	book := bookStore.FindBookById(id)
	if book == nil {
		w.WriteHeader(http.StatusNotFound)
		resp.Error = fmt.Sprintf("")
		respJson, _ := json.Marshal(resp)
		w.Write(respJson)
		return
	}
	resp.Message = book

	respJson, _ := json.Marshal(resp)
	w.WriteHeader(http.StatusOK)
	w.Write(respJson)
}

type Book struct {
	Id     string `json:"id"`
	Author string `json:"author"`
	Name   string `json:"name"`
}

type BookStore struct {
	books []Book
}

var bookStore = BookStore{
	books: make([]Book, 0),
}

func (s BookStore) FindBookById(id string) *Book {
	for _, book := range s.books {
		if book.Id == id {
			return &book
		}
	}
	return nil
}

func (s BookStore) GetBooks() []Book {
	return s.books
}

func (s *BookStore) AddBooks(book Book) error {
	for _, bk := range s.books {
		if bk.Id == book.Id {
			return errors.New(fmt.Sprintf("Book witch id %s not found", book.Id))
		}
	}
	s.books = append(s.books, book)
	return nil
}

func (s *BookStore) UpdateBook(book Book) error {
	for i, bk := range s.books {
		if bk.Id == book.Id {
			s.books[i] = book
			return nil
		}
	}
	return errors.New(fmt.Sprintf("Book with id %s not found", book.Id))
}

func (s *BookStore) DeleteBook(id string) error {
	for i, bk := range s.books {
		if bk.Id == id {
			s.books = append(s.books[:i], s.books[i+1:]...)
			return nil
		}
	}
	return errors.New(fmt.Sprintf("Book with id %s not found", id))
}

// DEL
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// DEL

type accountSP struct {
	databaseUsername string
	//databasePassword string
}

func signupPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		res.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(res, req, "app/views/layouts/account/signup.gohtml")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var accSP accountSP

	err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&accSP)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server:signupPage -> error, unable to create your account.[CODE:500]", 500)
			log.Printf("Server:signupPage -> status unable to create your account.")
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(res, "Server:signupPage ->  error, unable to create your account.[CODE:500]", 500)
			log.Printf("Server:signupPage -> error, unable to create your account.")
			return
		}

		res.Write([]byte("User created!"))
		return
	case err != nil:
		http.Error(res, "Server:signupPage -> error, unable to create your account.[CODE:500]", 500)
		log.Printf("Server:signupPage -> error, unable to create your account.")
		return
	default:
		http.Redirect(res, req, "/", 301)
	}
}

type accountLP struct {
	databaseUsername string
	databasePassword string
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		res.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(res, req, "app/views/layouts/account/login.gohtml")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	var accLP accountLP

	err := json.NewDecoder(req.Body).Decode(&accLP)
	if err != nil {
		err := db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&accLP.databaseUsername, &accLP.databasePassword)

		if err != nil {
			http.Redirect(res, req, "/login", 301)
			log.Printf("Server:loginPage -> status redirect /login.[CODE:301]")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(accLP.databasePassword), []byte(password))
		if err != nil {
			http.Redirect(res, req, "/login", 301)
			log.Printf("Server:loginPage -> status error wrong password redirect /login.[CODE:301]")
			return
		}

		res.Write([]byte("Hello " + accLP.databaseUsername))
		log.Printf("Server greets user: ", accLP.databaseUsername)
		return
	}
	// If the structure of the body is wrong, return an HTTP error
	res.WriteHeader(http.StatusBadRequest)
	log.Printf("Server:loginPage -> status bag request.")

	// Get the expected password from our in memory map
	expectedPassword, ok := users[accLP.databaseUsername]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != accLP.databasePassword {
		res.WriteHeader(http.StatusUnauthorized)
		log.Printf("Server:loginPage -> status Unauthorized.")
		return
	}

	// Create a new random session token
	sessionToken := uuid.Must(uuid.NewV4()).String()
	// Set the token in the cache, along with the user whom it represents
	// The token has an expiry time of 120 seconds
	/*
		_, err = cache.Do("SETEX", sessionToken, "120", accLP.databaseUsername)
		if err != nil {
			// If there is an error in setting the cache, return an internal server error
			res.WriteHeader(http.StatusInternalServerError)
			log.Printf("Server:loginPage -> status internal server error.[SETEX]")
			return
		}
	*/

	// Finally, we set the client cookie for "session_token" as the session token we just generated
	// we also set an expiry time of 120 seconds, the same as the cache
	http.SetCookie(res, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(120 * time.Second),
	})

	//var databaseUsername string
	//var databasePassword string

	/* db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&accLP.databaseUsername, &accLP.databasePassword)

	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(accLP.databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	res.Write([]byte("Hello " + accLP.databaseUsername))
	*/

}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	if url == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		templates.ExecuteTemplate(w, "index.gohtml", nil)

		var accLP accountLP

		w.Write([]byte("Hello " + accLP.databaseUsername))
		log.Printf("Server:indexHandler status user hello.")
		return
	}
}

func indexManage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.ExecuteTemplate(w, "app/views/layouts/manage/manage.gohtml", nil)
	log.Printf("Server: Call indexManager, WARNING!.")
	// We can obtain the session token from the requests cookies, which come with every request

	//c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("Server:indexManager -> status unauthorized user.")
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("Server:indexManager -> status bad request.")
		return
	}
	//sessionToken := c.Value

	/*
			// We then get the name of the user from our cache, where we set the session token
			response, err := cache.Do("GET", sessionToken)
			if err != nil {
				// If there is an error fetching from cache, return an internal server error status
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("Server:indexManager -> status internal error.[GET]")
				return
			}
		if response == nil {
			// If the session token is not present in cache, return an unauthorized error
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("Server:indexManger -> status unauthorized.")
			return
		}
		// Finally, return the welcome message to the user
		w.Write([]byte(fmt.Sprintf("Welcome %s!", response)))
	*/
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	//c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("Server:Refresh -> status unauthorized.")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("Server:Refresh -> status bar request.")
		return
	}
	//sessionToken := c.Value

	/*
				response, err := cache.Do("GET", sessionToken)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Printf("Server:Refresh -> status internal server error.[GET]")
					return
				}

			if response == nil {
				w.WriteHeader(http.StatusUnauthorized)
				log.Printf("Server:Refresh -> status unauthorized.")
				return
			}
			// (END) The code uptil this point is the same as the first part of the `Welcome` route

			// Now, create a new session token for the current user
			newSessionToken := uuid.Must(uuid.NewV4()).String()
			_, err = cache.Do("SETEX", newSessionToken, "120", fmt.Sprintf("%s", response))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("Server:Refresh -> status internal server error.[SETEX]")
				return
			}

			// Delete the older session token
			_, err = cache.Do("DEL", sessionToken)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("Server:Refresh -> status internal server error.[DEL]")
				return
			}

		// Set the new token as the users `session_token` cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   newSessionToken,
			Expires: time.Now().Add(120 * time.Second),
		})
	*/
}
