package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	if !setupExists() {
		doSetup()
	}
	runCLI()
}

func setupExists() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return false
	}

	path := filepath.Join(homeDir, ".LockSmith")
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return true
	}
	return false
}

func doSetup() {
	fmt.Println("Guess this is the first time LockSmith is being set up on your device.")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return
	}

	dirPath := filepath.Join(homeDir, ".LockSmith")
	fmt.Println("Step 1: Setting up the .LockSmith directory in your user home directory...")

	err = os.MkdirAll(dirPath, 0755) // MkdirAll ensures parent directories exist
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	fmt.Println("Step 2: Setting up a master password")
	masterPassword := setupMasterPassword()
	if masterPassword == "" {
		fmt.Println("Master password setup failed.")
		return
	}

	passwordFilePath := filepath.Join(dirPath, "master_password")
	err = os.WriteFile(passwordFilePath, []byte(masterPassword), 0600) // Secure file permissions
	if err != nil {
		fmt.Println("Error saving master password:", err)
		return
	}

	fmt.Println("Setup successful!")
}

func setupMasterPassword() string {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter a master password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		fmt.Print("Confirm your master password: ")
		confirmPassword, _ := reader.ReadString('\n')
		confirmPassword = strings.TrimSpace(confirmPassword)

		if password == confirmPassword && password != "" {
			hashedPassword := hashPassword(password)
			fmt.Println("Master password set successfully!")
			return hashedPassword
		} else {
			fmt.Println("Passwords do not match or are empty. Please try again.")
		}
	}
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// runCLI prompts the user for their master password to unlock the blackbox,
// then provides a menu to generate new passwords, retrieve stored ones, or list stored IDs.
func runCLI() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your master password to unlock: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// Read stored master hash
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return
	}
	masterHashPath := filepath.Join(homeDir, ".LockSmith", "master_password")
	storedHashBytes, err := os.ReadFile(masterHashPath)
	if err != nil {
		fmt.Println("Error reading master password file:", err)
		return
	}

	if hashPassword(input) != string(storedHashBytes) {
		fmt.Println("Invalid master password!")
		return
	}

	// Derive encryption key from the plain master password.
	key := sha256.Sum256([]byte(input))

	// Load or initialize the blackbox data.
	data := loadBlackbox(key[:])

	// Main CLI loop.
	for {
		fmt.Println("\nChoose an option:")
		fmt.Println("1. Generate and store a new password")
		fmt.Println("2. Retrieve a stored password")
		fmt.Println("3. List all stored password IDs")
		fmt.Println("4. Exit")
		fmt.Print("Enter choice: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Print("Enter an ID for the password: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			fmt.Print("Enter desired length for the password: ")
			lenStr, _ := reader.ReadString('\n')
			lenStr = strings.TrimSpace(lenStr)
			length, err := strconv.Atoi(lenStr)
			if err != nil || length <= 0 {
				fmt.Println("Invalid length provided, using default length 16")
				length = 16
			}
			newPassword := generatePassword(length)
			data[id] = newPassword
			saveBlackbox(key[:], data)
			fmt.Println("New password generated and stored with ID:", id)
		case "2":
			fmt.Print("Enter the ID of the password to retrieve: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			if pass, ok := data[id]; ok {
				fmt.Printf("Password for '%s': %s\n", id, pass)
			} else {
				fmt.Println("No password found with that ID.")
			}
		case "3":
			fmt.Println("Stored password IDs:")
			for id := range data {
				fmt.Println(" -", id)
			}
		case "4":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}

// loadBlackbox loads and decrypts the password store from the blackbox file.
// If the file doesn't exist or decryption fails, it returns an empty map.
func loadBlackbox(key []byte) map[string]string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return make(map[string]string)
	}
	filePath := filepath.Join(homeDir, ".LockSmith", "blackbox")
	dataMap := make(map[string]string)
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		// If file does not exist, return an empty map.
		return dataMap
	}
	if len(ciphertext) == 0 {
		return dataMap
	}
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		fmt.Println("Error decrypting blackbox:", err)
		return dataMap
	}
	err = json.Unmarshal(plaintext, &dataMap)
	if err != nil {
		fmt.Println("Error parsing blackbox data:", err)
		return make(map[string]string)
	}
	return dataMap
}

// saveBlackbox encrypts and writes the password store to the blackbox file.
func saveBlackbox(key []byte, dataMap map[string]string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return
	}
	filePath := filepath.Join(homeDir, ".LockSmith", "blackbox")
	plaintext, err := json.Marshal(dataMap)
	if err != nil {
		fmt.Println("Error encoding data:", err)
		return
	}
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}
	err = os.WriteFile(filePath, ciphertext, 0600)
	if err != nil {
		fmt.Println("Error writing blackbox file:", err)
	}
}

// encrypt uses AES-GCM to encrypt the plaintext with the provided key.
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt uses AES-GCM to decrypt the ciphertext with the provided key.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// generatePassword creates a random password of the given length using a charset.
func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?/|"
	password := make([]byte, length)
	for i := range password {
		// Choose a random index into the charset.
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		password[i] = charset[num.Int64()]
	}
	return string(password)
}
