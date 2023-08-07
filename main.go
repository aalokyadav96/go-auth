package main

import (
	"fmt"
	"log"
	"errors"
	"net/http"
    "encoding/hex"

	"github.com/gorilla/securecookie"
	"github.com/julienschmidt/httprouter"
)


var secretKey []byte

func main() {
	var err error
	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
    if err != nil {
        log.Fatal(err)
    }

	router := httprouter.New()
	router.GET("/", indexPageHandler)
	router.GET("/internal", internalPageHandler)
	router.GET("/login", loginHandler)
	router.POST("/login", loginHandler)
	router.POST("/logout", logoutHandler)

	log.Fatal(http.ListenAndServe("localhost:4000", router))
}



var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func getUserName(r *http.Request, w http.ResponseWriter) (userName string) {
    value, err := ReadEncrypted(r, "session", secretKey)
    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            http.Error(w, "cookie not found", http.StatusBadRequest)
        case errors.Is(err, ErrInvalidValue):
            http.Error(w, "invalid cookie", http.StatusBadRequest)
        default:
            log.Println(err)
            http.Error(w, "server error", http.StatusInternalServerError)
        }
        return
    }
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	return userName
}

func setSession(userName string, w http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		err := WriteEncrypted(w, cookie, secretKey)
		if err != nil {
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
}

func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

// login handler

func loginHandler(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
	redirectTarget := "/"
	if name != "" && pass != "" {
		// .. check credentials ..
		setSession(name, response)
		redirectTarget = "/internal"
	}
	http.Redirect(response, request, redirectTarget, 302)
}

// logout handler

func logoutHandler(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	clearSession(response)
	http.Redirect(response, request, "/", 302)
}

// index page

const indexPage = `
<h1>Login</h1>
<form method="post" action="/login">
    <label for="name">User name</label>
    <input type="text" id="name" name="name">
    <label for="password">Password</label>
    <input type="password" id="password" name="password">
    <button type="submit">Login</button>
</form>
`

func indexPageHandler(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	fmt.Fprintf(response, indexPage)
}

// internal page

const internalPage = `
<h1>Internal</h1>
<hr>
<small>User: %s</small>
<form method="post" action="/logout">
    <button type="submit">Logout</button>
</form>
`

func internalPageHandler(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	userName := getUserName(request, response)
	if userName != "" {
		fmt.Fprintf(response, internalPage, userName)
	} else {
		http.Redirect(response, request, "/", 302)
	}
}