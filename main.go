package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var password string

	// Root command
	var rootCmd = &cobra.Command{
		Use:   "fcypt",
		Short: "A simple file encryption/decryption tool",
		Long:  `fcypt is a lightweight CLI tool to encrypt and decrypt files using AES-256-GCM.`,
	}

	// Persistent flags
	rootCmd.PersistentFlags().StringVarP(&password, "pass", "p", "", "Password for encryption/decryption")
	rootCmd.MarkPersistentFlagRequired("pass")

	// Encrypt subcommand
	var encCmd = &cobra.Command{
		Use:   "enc [file]",
		Short: "Encrypt a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			processFile(args[0], password, true)
		},
	}

	// Decrypt subcommand
	var decCmd = &cobra.Command{
		Use:   "dec [file]",
		Short: "Decrypt a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			processFile(args[0], password, false)
		},
	}

	rootCmd.AddCommand(encCmd, decCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// processFile handles the logic for both encryption and decryption
func processFile(filename string, password string, encrypt bool) {
	// Derive a 32-byte key from the password using SHA256
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error: could not read file: %v\n", err)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error: could not create cipher: %v\n", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error: could not create GCM: %v\n", err)
		return
	}

	if encrypt {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Printf("Error: could not generate nonce: %v\n", err)
			return
		}

		// Ciphertext = nonce + sealed data
		out := gcm.Seal(nonce, nonce, data, nil)
		newName := filename + ".enc"
		err = os.WriteFile(newName, out, 0644)
		if err != nil {
			fmt.Printf("Error: could not save encrypted file: %v\n", err)
			return
		}
		fmt.Printf("Success! File encrypted as: %s\n", newName)
	} else {
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			fmt.Println("Error: ciphertext too short or invalid file format")
			return
		}

		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Println("Error: decryption failed (wrong password or corrupted data)")
			return
		}

		newName := "decrypted_" + filename
		err = os.WriteFile(newName, plaintext, 0644)
		if err != nil {
			fmt.Printf("Error: could not save decrypted file: %v\n", err)
			return
		}
		fmt.Printf("Success! File decrypted as: %s\n", newName)
	}
}
