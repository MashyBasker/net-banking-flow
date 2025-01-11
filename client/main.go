package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"
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

type OTPDetails struct {
	Pin	int	`json:"pin"`
}

var isLoggedIn bool
var loggedInUser string

func main() {
	for {
		fmt.Println("\n=== Banking System ===")
		fmt.Println("1. Login")
		fmt.Println("2. Fund Transfer")
		fmt.Println("3. OTP validation")
		fmt.Println("4. Exit")
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
		case 4:
			fmt.Println("[+] Exiting the program. Goodbye!")
			os.Exit(0)
		case 3:
			if isLoggedIn {
				otpValidation()
			}
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


func otpValidation() {
	// write a random OTP pin in a file
	rand.Seed(time.Now().UnixNano())
	otpRandom := 100000 + rand.Intn(900000)
	otpFilePath := "./database/otp.txt"
	file, err := os.Create(otpFilePath)
	if err != nil {
		fmt.Println("[*] Failed to create the file: ", err)
		return
	}

	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%d\n", otpRandom))
	if err != nil {
		fmt.Printf("[*] Failed to write to the file: %v\n", err)
		return
	}

	var otpPin int
	fmt.Println("Enter the OTP you received: ")
	_, err = fmt.Scan(&otpPin)
	if err != nil {
		fmt.Println("[*] Unable to get user input")
		return
	}

	otp := OTPDetails {
		Pin: otpPin,
	}

	data, err := json.Marshal(otp)
	if err != nil {
		fmt.Println("[*] Error marshalling login data")
		return
	}

	resp, err := http.Post("http://localhost:8081/encryptOtp", "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[*] Error sending OTP pin to PQC sever")
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("[*] OTP validation failed. Sever responded with error")
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Response: ", string(body))
		return
	}

	fmt.Println("[+] OTP validation request sent")
}