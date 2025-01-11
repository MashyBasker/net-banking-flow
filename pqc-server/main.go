package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// storing the public key and secret key
// in the PQC server
var (
	pk *mlkem1024.PublicKey
	sk *mlkem1024.PrivateKey
)

type LoginDetails struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TransferDetails struct {
	Sender 		string 	`json:"sender"`
	Recipient	string 	`json:"recipient"`
	Amount		float64 `json:"amount"`
}

func initKeys() {
	scheme := mlkem1024.Scheme()
	pubKey, privKey, _ := scheme.GenerateKeyPair()
	fmt.Println("[+] Key generation successful")
	pk = pubKey.(*mlkem1024.PublicKey)
	sk = privKey.(*mlkem1024.PrivateKey)
}

func encryptLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}


	var loginDetails LoginDetails
	err := json.NewDecoder(r.Body).Decode(&loginDetails)
	if err != nil {
		fmt.Println("[*] Error decoding request body")
		return
	}

	fmt.Println("[+] Decoded the incoming login details into JSON")
	loginDetailsJSON, err := json.Marshal(loginDetails)
	if err != nil {
		fmt.Println("[*] Failed to encode LoginDetails to JSON")
		return
	}

	scheme := mlkem1024.Scheme()

	ciphertext, sharedSecret, err := scheme.Encapsulate(pk)
	if err != nil {
		http.Error(w, "[*] Key Encapsulation failed", http.StatusBadRequest)
		return
	}
	fmt.Println("[+] Key encapsulation with ML-KEM successful")

	block, err := aes.NewCipher(sharedSecret[:16])
	if err != nil {
		fmt.Println("[*] Failed to create AES cipher block: ", err)
		http.Error(w, "[*] Failed to create AES cipher block", http.StatusInternalServerError)
		return
	}

	fmt.Println("[+] AES Cipher created successfully")

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "[*] Failed to create AES-GCM cipher", http.StatusInternalServerError)
		fmt.Println("[*] Failed to create AES-GCM cipher: ", err)
		return
	}

	fmt.Println("[+] AES-GCM Cipher created successfully")

	nonce := make([]byte, aesGCM.NonceSize())
	encryptedData := aesGCM.Seal(nil, nonce, loginDetailsJSON, nil)
	fmt.Println("[+] Encryption successful")
	fmt.Printf("[+] Encrypted data(in base64): %s\n", base64.StdEncoding.EncodeToString(encryptedData))

	response := map[string][]byte{
		"kemCiphertext": ciphertext,
		"encryptedData": encryptedData,
		"nonce":         nonce,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "[*] Failed to serialize response", http.StatusInternalServerError)
		fmt.Println("[*] Failed to serialize response payload: ", err)
		return
	}

	bankserverURL := "http://localhost:8082/receive"
	resp, err := http.Post(bankserverURL, "application/json", bytes.NewBuffer(responseJSON))
	if err != nil {
		http.Error(w, "[*] Failed to send data to bank server", http.StatusInternalServerError)
		fmt.Println("[*] Failed to send data to bank server: ", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("[+] Successfully sent encrypted data to bank server")
	} else {
		fmt.Println("[*] Failed to send encrypted data to bank server")
		http.Error(w, "Bank server rejected the request", resp.StatusCode)
	}
		
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func decryptLoginHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		KemCiphertext []byte `json:"kemCiphertext"`
		EncryptedData []byte `json:"encryptedData"`
		Nonce         []byte `json:"nonce"`
	}
	scheme := mlkem1024.Scheme()
	err := json.NewDecoder(r.Body).Decode(&requestData)

	if err != nil {
		http.Error(w, "[*] Invalid: Malformed request", http.StatusBadRequest)
		fmt.Println("[*] The decryption request is invalid")
		return
	}

	defer r.Body.Close()
	sharedSecret, err := scheme.Decapsulate(sk, requestData.KemCiphertext)
	// fmt.Println("[DEBUG] SK at Login: ", sk)
	if err != nil {
		http.Error(w, "Decapsulation failed", http.StatusInternalServerError)
		return
	}

	block, err := aes.NewCipher(sharedSecret[:16])
	// fmt.Println("[DEBUG] Block during Login: ", block)
	if err != nil {
		http.Error(w, "Failed to create cipher block", http.StatusInternalServerError)
		return
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Failed to create AES-GCM cipher", http.StatusInternalServerError)
		return
	}

	plaintext, err := aesGCM.Open(nil, requestData.Nonce, requestData.EncryptedData, nil)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
	}
	fmt.Println("[+] Decryption successful")
	fmt.Println("[+] Decrypted data: ", string(plaintext))

	var loginDetails LoginDetails
	err = json.Unmarshal(plaintext, &loginDetails)
	if err != nil {
		fmt.Println("[*] Failed to parse decrypted data into JSON")
		return
	}

	fmt.Println("[+] Parsed decrypted data into LoginDetails struct") 
	loginDetailsJSON, err := json.Marshal(loginDetails)
	if err != nil {
		fmt.Println("[*] Failed to encode LoginDetails as JSON")
		return
	}

	bankserverURL := "http://localhost:8082/validate"
	fmt.Printf("[+] Sending decrypted login details to bank server: %s\n", loginDetailsJSON)
	response, err := http.Post(bankserverURL, "application/json", bytes.NewBuffer(loginDetailsJSON))
	if err != nil {
		http.Error(w, "[*] failed to send decrypted data to bank server", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	fmt.Println("[+] Response from bank server ", response.StatusCode, response.Status)

	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)

}

func encryptTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fmt.Println("[*] Invalid Request Method")
		return
	}

	var transferDetails TransferDetails
	err := json.NewDecoder(r.Body).Decode(&transferDetails)
	// body, err := io.ReadAll(r.Body)
	// if err != nil {
		// fmt.Println(err)
	// }

	if err != nil {
		fmt.Println("[*] Invalid: Malformed request")
	}

	fmt.Println("[+] Successfully Decoded transfer details to JSON")
	transferDetailsJSON, err := json.Marshal(transferDetails)

	if err != nil {
		fmt.Println("[*] Failed to encode TransferDetails to JSON")
		return
	}
	scheme := mlkem1024.Scheme()

	ciphertext, sharedSecret, err := scheme.Encapsulate(pk)
	if err != nil {
		http.Error(w, "Key encapsulation failed", http.StatusInternalServerError)
		fmt.Println("[*] Key encapsulation failed")
		return
	}

	fmt.Println("[+] Key encapsulation with ML-KEM sucessful")
	block, err := aes.NewCipher(sharedSecret[:16])
	if err != nil {
		http.Error(w, "Failed to create AES cipher block", http.StatusInternalServerError)
		fmt.Println("[*] Failed to create AES cipher block")
		return
	}
	fmt.Println("[+] AES Cipher created successfully")

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Failed to create AES-GCM cipher", http.StatusInternalServerError)
		fmt.Println("[*] Failed to create AES-GCM cipher")
		return
	}
	fmt.Println("[+] AES-GCM Cipher created successfully")
	nonce := make([]byte, aesGCM.NonceSize())
	encryptedData := aesGCM.Seal(nil, nonce, transferDetailsJSON, nil)
	fmt.Println("[+] Encryption successful")
	fmt.Printf("[+] Encrypted data transfer (in base64): %s\n", base64.StdEncoding.EncodeToString(encryptedData))
	
	response := map[string][]byte {
		"kemCipherText": ciphertext,
		"encryptedData": encryptedData,
		"nonce":		 nonce,
	}

	// fmt.Printf("[DEBUG] KemCiphertext: %x\n", ciphertext)
	// fmt.Printf("[DEBUG] Nonce: %x\n", nonce)
	// fmt.Printf("[DEBUG] Encrypted data: %x\n", encryptedData)
	// fmt.Printf("[DEBUG] shared secret: %x\n", sharedSecret)

	responseJSON, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		fmt.Println("[*] Failed to serialize response")
		return
	}

	bankserverURL := "http://localhost:8082/recieveTransfer"
	resp, err := http.Post(bankserverURL, "application/json", bytes.NewBuffer(responseJSON))

	// fmt.Println("[DEBUG] payload to bank server: ", string(responseJSON))
	if err != nil {
		http.Error(w, "Failed to send encrypted transfer data to bank server", http.StatusInternalServerError)
		fmt.Println("[*] Failed to send encrypted transfer data to bank server")
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("[+] Successfully sent encrypted fund transfer request to bank")
	} else {
		fmt.Println("[*] Failed to send encrypted fund transfer request to bank")
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJSON)
}

func decryptTransferHandler(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		KemCiphertext	[]byte	`json:"kemCiphertext"`
		EncryptedData	[]byte	`json:"encryptedData"`
		Nonce			[]byte	`json:"nonce"`
	}

	scheme := mlkem1024.Scheme()
	err := json.NewDecoder(r.Body).Decode(&requestData)

	if err != nil {
		http.Error(w, "[*] Invalid: Malformed request", http.StatusBadRequest)
		fmt.Println("[*] The decryption request is invalid")
		return
	}

	defer r.Body.Close()
	sharedSecret, err := scheme.Decapsulate(sk, requestData.KemCiphertext)

	// fmt.Printf("[DEBUG] KemCiphertext: %x\n", requestData.KemCiphertext)
	// fmt.Printf("[DEBUG] Nonce: %x\n", requestData.Nonce)
	// fmt.Printf("[DEBUG] Encrypted data: %x\n", requestData.EncryptedData)
	// fmt.Printf("[DEBUG] shared secret: %x\n", sharedSecret)
	// fmt.Println("[DEBUG] SK at fund transfer: ", sk)
	if err != nil {
		http.Error(w, "Decapsulation failed", http.StatusInternalServerError)
		fmt.Println("[*] Key decapsulation failed", http.StatusInternalServerError)
		return
	}
	fmt.Println("[+] Key Decapsulation successful")
	block, err := aes.NewCipher(sharedSecret[:16])
	// fmt.Println("[DEBUG] Block during Fund Transfer: ", block)
	if err != nil {
		http.Error(w, "Failed to create cipher block", http.StatusInternalServerError)
		return
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "Failed to create AES-GCM cipher", http.StatusInternalServerError)
		fmt.Println("[*] AES-GCM cipher could not be created")
		return 
	}

	plaintext, err := aesGCM.Open(nil, requestData.Nonce, requestData.EncryptedData, nil)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		fmt.Println("[*] Decryption failed: ", err)
		return
	}
	
	fmt.Println("[+] Decryption successful")
	fmt.Println("[+] Decrypted data: ", string(plaintext))

	var transferDetails TransferDetails
	err = json.Unmarshal(plaintext, &transferDetails)
	if err != nil {
		fmt.Println("[*] Failed to encode login details as JSON")
		return
	}

	fmt.Println("[+] Parsed decrypted data into TransferDetails struct")
	transferDetailsJSON, err := json.Marshal(transferDetails)
	if err != nil {
		fmt.Println("[*] Failed to encode TransferDetails to JSON")
		return
	}

	bankserverURL := "http://localhost:8082/validateTransfer"
	fmt.Printf("[+] Sending decrypted fund transfer details to bank server: %s\n", transferDetailsJSON)
	response, err := http.Post(bankserverURL, "application/json", bytes.NewBuffer(transferDetailsJSON))
	if err != nil {
		http.Error(w, "[*] failed to send decrypted data to bank server", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	fmt.Println("[+] Response from bank server: ", response.StatusCode, " ", response.Status)

	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}


func main() {
	initKeys()
	http.HandleFunc("/encrypt", encryptLoginHandler)
	http.HandleFunc("/decrypt", decryptLoginHandler)
	http.HandleFunc("/encryptTransfer", encryptTransferHandler)
	http.HandleFunc("/decryptTransfer", decryptTransferHandler)
	fmt.Println("[+] PQC server running on port 8081")
	http.ListenAndServe(":8081", nil)
}
