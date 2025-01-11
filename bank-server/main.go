package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type UserData struct {
	Username string
	Password string
	Funds 	 string
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

func recieveTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "[*] Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "[*] Failed to decode encrypted data", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()


	pqcURL := "http://localhost:8081/decryptTransfer"
	resp, err := http.Post(pqcURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("[*] Failed to forward data to PQC server")
		return
	}

	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func receiveOtpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "[*] Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "[*] Failed to decode encrypted data", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	pqcURL := "http://localhost:8081/decryptOtp"
	resp, err := http.Post(pqcURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("[*] Failed to forward OTP data to PQC server")
		return
	}

	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func validateTransferHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Sender		string	`json:"sender"`
		Recipient	string	`json:"recipient"`
		Amount		float64	`json:"amount"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	fmt.Println("[+] Recieved fund transfer request")

	file, err := os.Open("./database/db.csv")
	if err != nil {
		fmt.Printf("Failed to open csv file %v\n", err)
		return
	}

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("failed to read database")
		return
	}

	var senderIndex, recipientIndex = -1, -1
	var senderBalance, recipientBalance float64
	amount := requestData.Amount

	for i, record := range records {
		if record[0] == requestData.Sender {
			senderIndex = i
			senderBalance, err = strconv.ParseFloat(record[2], 64)
			if err != nil {
				fmt.Println("[*] Invalid balance")
				return
			}
		} else if record[0] == requestData.Recipient {
			recipientIndex = i
			recipientBalance, err = strconv.ParseFloat(record[2], 64)
			if err != nil {
				fmt.Println("[*] Invalid balance")
				return
			}
		}
	}

	if senderIndex == -1 {
		fmt.Println("[*] Sender not found")
		return
	}

	if recipientIndex == -1 {
		fmt.Println("[*] Recipient not found")
		return
	}

	records[senderIndex][2] = fmt.Sprintf("%.2f", senderBalance - amount)
	records[recipientIndex][2] = fmt.Sprintf("%.2f", recipientBalance + amount)

	file, err = os.Create("./database/db.csv")
	if err != nil {
		fmt.Println("[*] Faiiled to create database")
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, record := range records {
		if err := writer.Write(record); err != nil {
			fmt.Println("[*] Failed to write to database")
			return
		}
	}
	
	fmt.Printf("[+] %s's new balance: %s\n", records[senderIndex][0], records[senderIndex][2])
	fmt.Printf("[+] %s's new balance: %s\n", records[recipientIndex][0], records[recipientIndex][2])
}

func validateOtpHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Pin	int	`json:"pin"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	fmt.Println("[+] Received OTP validation request")
	otpFromUser := requestData.Pin
	file, err := os.Open("./database/otp.txt")
	if err != nil {
		fmt.Println("failed to open OTP file")
		return
	}
	defer file.Close()
	var firstLine string
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		firstLine = scanner.Text()
		fmt.Println("[+] OTP read from file")
	} else {
		fmt.Println("[*] No content in file")
	}

	otpFromSystem, err:= strconv.Atoi(firstLine)
	if err != nil {
		fmt.Println("[+] Error converting to integer ", err)
		return
	}

	if otpFromSystem == otpFromUser {
		fmt.Println("[+] OTP validation successful")
	} else {
		fmt.Println("[+] OTP validation failed")
	}
}

func main() {
	err := loadUsers()
	if err != nil {
		fmt.Println("[*] Error loading users")
		return
	}
	http.HandleFunc("/validate", validateHandler)
	http.HandleFunc("/receive", receiveHandler)
	http.HandleFunc("/recieveTransfer", recieveTransferHandler)
	http.HandleFunc("/validateTransfer", validateTransferHandler)
	http.HandleFunc("/receiveOtp", receiveOtpHandler)
	http.HandleFunc("/validateOtp", validateOtpHandler)
	fmt.Println("[+] Bank server running on port 8082")
	err = http.ListenAndServe(":8082", nil)
	if err != nil {
		fmt.Println("[*] Error starting server")
	}
}