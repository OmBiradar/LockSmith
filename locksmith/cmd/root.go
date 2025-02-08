package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var (
	length     int
	useSymbols bool
	useNumbers bool
	saveHash   bool
	copyToClip bool
)

var rootCmd = &cobra.Command{
	Use:   "passgen",
	Short: "Generate secure random passwords",
	Run: func(cmd *cobra.Command, args []string) {
		password, err := generatePassword(length, useSymbols, useNumbers)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		fmt.Println("Generated Password:", password)

		if copyToClip {
			if err := clipboard.WriteAll(password); err != nil {
				fmt.Println("⚠️ Failed to copy to clipboard:", err)
			} else {
				fmt.Println("✅ Copied to clipboard!")
			}
		}

		if saveHash {
			hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				fmt.Println("🔒 Failed to generate hash:", err)
				return
			}
			if err := os.WriteFile("password.hash", hashed, 0600); err != nil {
				fmt.Println("💾 Hash save failed:", err)
			} else {
				fmt.Println("🔒 Password hash saved to password.hash")
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IntVarP(&length, "length", "l", 16, "Password length")
	rootCmd.Flags().BoolVarP(&useSymbols, "symbols", "s", true, "Include symbols")
	rootCmd.Flags().BoolVarP(&useNumbers, "numbers", "n", true, "Include numbers")
	rootCmd.Flags().BoolVar(&saveHash, "save-hash", false, "Save bcrypt hash to file")
	rootCmd.Flags().BoolVarP(&copyToClip, "copy", "c", true, "Copy to clipboard")
}

// Secure password generation
func generatePassword(length int, useSymbols, useNumbers bool) (string, error) {
	if length < 8 {
		return "", errors.New("password length must be at least 8")
	}

	var chars strings.Builder
	chars.WriteString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	if useNumbers {
		chars.WriteString("0123456789")
	}

	if useSymbols {
		chars.WriteString("!@#$%^&*()-_=+,.?/:;{}[]~")
	}

	charSet := chars.String()
	password := make([]byte, length)
	max := big.NewInt(int64(len(charSet)))

	for i := range password {
		val, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("random generation failed: %v", err)
		}
		password[i] = charSet[val.Int64()]
	}

	return string(password), nil
}
