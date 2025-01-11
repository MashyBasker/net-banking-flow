package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type LoginDetails struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TransferDetails struct {
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
}

var isLoggedIn bool
var loggedInUser string

func main() {
	for {
		fmt.Println("\n=== Banking System ===")
		fmt.Println("1. Login")
		fmt.Println("2. Fund Transfer")
		fmt.Println("3. Exit")
		fmt.Printf("Enter your choice: ")

		var choice int
		fmt.Scan(&choice)

		switch choice {
		case 1:
			login()
		case 2:
			if isLoggedIn {
				fundTransfer()
			} else {
				fmt.Println("[*] You must log in before making a fund transfer.")
			}
		case 3:
			fmt.Println("[+] Exiting the program. Goodbye!")
			os.Exit(0)
		default:
			fmt.Println("[*] Invalid choice. Please try again.")
		}
	}
}

func login() {
	var newUserName string
	var newPassword string
	fmt.Printf("Enter your username: ")
	fmt.Scan(&newUserName)
	fmt.Printf("Enter your password: ")
	fmt.Scan(&newPassword)

	login := LoginDetails{
		Username: newUserName,
		Password: newPassword,
	}

	data, err := json.Marshal(login)
	if err != nil {
		fmt.Println("[*] Error marshalling login data.")
		return
	}

	resp, err := http.Post("http://localhost:8081/encrypt", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[*] Error sending login data to PQC server.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("[*] Login failed. Server responded with an error.")
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Response:", string(body))
		return
	}

	fmt.Println("[+] Login successful.")
	isLoggedIn = true
	loggedInUser = newUserName
}

func fundTransfer() {
	var recipient string
	var amount float64
	fmt.Printf("Enter recipient account ID: ")
	fmt.Scan(&recipient)
	fmt.Printf("Enter the amount to transfer: ")
	fmt.Scan(&amount)

	transfer := TransferDetails{
		Sender:    loggedInUser,
		Recipient: recipient,
		Amount:    amount,
	}

	transferData, err := json.Marshal(transfer)
	if err != nil {
		fmt.Println("[*] Error marshalling transfer details.")
		return
	}

	resp, err := http.Post("http://localhost:8081/encryptTransfer", "application/json", bytes.NewBuffer(transferData))
	if err != nil {
		fmt.Println("[*] Error sending transfer request to bank server.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("[+] Transfer Request sent")
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("[+] Response:", string(body))
		return
	}

	fmt.Println("[+] Fund transfer request set.")
}
