package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings" // 1. 引入 strings 包

	"github.com/spf13/cobra"
)

func main() {
	var password string

	var rootCmd = &cobra.Command{
		Use:   "fcrypt",
		Short: "A simple file encryption/decryption tool",
		Long:  `fcrypt is a lightweight CLI tool to encrypt and decrypt files using AES-256-GCM.`,
	}

	rootCmd.PersistentFlags().StringVarP(&password, "pass", "p", "", "Password for encryption/decryption")
	rootCmd.MarkPersistentFlagRequired("pass")

	var encCmd = &cobra.Command{
		Use:   "enc [file]",
		Short: "Encrypt a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			processFile(args[0], password, true)
		},
	}

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

func processFile(filename string, password string, encrypt bool) {
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

		// --- 修改部分开始 ---
		var newName string
		if strings.HasSuffix(filename, ".enc") {
			// 如果文件名以 .enc 结尾，则去掉它
			newName = strings.TrimSuffix(filename, ".enc")
		} else {
			// 如果不是，则加上 decrypted_ 前缀防止覆盖原文件
			newName = "decrypted_" + filename
		}
		// --- 修改部分结束 ---

		err = os.WriteFile(newName, plaintext, 0644)
		if err != nil {
			fmt.Printf("Error: could not save decrypted file: %v\n", err)
			return
		}
		fmt.Printf("Success! File decrypted as: %s\n", newName)
	}
}
