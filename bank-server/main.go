package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type UserData struct {
	Username string
	Password string
}

var userDB []UserData

func loadUsers() error {
	file, err := os.Open("./database/db.csv")
	if err != nil {
		return fmt.Errorf("failed to open csv file %v", err)
	}

	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read csv file %v", err)
	}

	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		userDB = append(userDB, UserData{
			Username: row[0],
			Password: row[1],
		})
	}
	return nil
}

func validateHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	fmt.Printf("[+] Recieved login request\n")
	var validUser *UserData
	for _, user := range userDB {
		if strings.EqualFold(user.Username, requestData.Username) && user.Password == requestData.Password {
			validUser = &user
			break
		}
	}
	
	if validUser != nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[+] Login successful"))
		fmt.Println("[+] Login successful")
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		fmt.Println("[+] Login failed")
	}
}

func receiveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "[*] Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// get the encrypted data from the PQC server
	encryptedData, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "[*] Failed to decode encrypted data", http.StatusInternalServerError)
	}

	fmt.Println("[+] Received encrypted data from PQC server: ", string(encryptedData))

	pqcURL := "http://localhost:8081/decrypt"
	resp, err := http.Post(pqcURL, "application/json", bytes.NewBuffer(encryptedData))
	if err != nil {
		http.Error(w, "[*] Failed to send data to PQC server", http.StatusInternalServerError)
	}
	// fmt.Println("[+] Encrypted data sent to PQC server for decryption")
	defer resp.Body.Close()
}

func main() {
	err := loadUsers()
	if err != nil {
		fmt.Println("[*] Error loading users")
		return
	}
	http.HandleFunc("/validate", validateHandler)
	http.HandleFunc("/receive", receiveHandler)
	fmt.Println("[+] Bank server running on port 8082")
	err = http.ListenAndServe(":8082", nil)
	if err != nil {
		fmt.Println("[*] Error starting server")
	}
}