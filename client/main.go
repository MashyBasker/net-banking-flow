package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type LoginDetails struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	var newUserName string
	var newPassword string
	fmt.Printf("Enter a username: ")
	fmt.Scan(&newUserName)
	fmt.Printf("Enter a password: ")
	fmt.Scan(&newPassword)

	login := LoginDetails{
		Username: newUserName,
		Password: newPassword,
	}

	data, err := json.Marshal(login)
	if err != nil {
		fmt.Println("Marshalling error")
		return
	}

	resp, err := http.Post("http://localhost:8081/encrypt", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error sending data to PQC server")
		return
	}
	defer resp.Body.Close()
	fmt.Println("[+] Login data sent to PQC server for encryption")
}
