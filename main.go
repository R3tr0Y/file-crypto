package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath" // 用于处理通配符
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var password string
	var removeSource bool // 新增 flag 变量

	var rootCmd = &cobra.Command{
		Use:   "fcrypt",
		Short: "A simple file encryption/decryption tool",
		Long:  `fcrypt is a lightweight CLI tool to encrypt and decrypt files using AES-256-GCM. Supports wildcards like *.txt`,
	}

	// 全局 Flag
	rootCmd.PersistentFlags().StringVarP(&password, "pass", "p", "", "Password for encryption/decryption")
	rootCmd.PersistentFlags().BoolVarP(&removeSource, "remove", "r", false, "Remove source file after successful processing")
	rootCmd.MarkPersistentFlagRequired("pass")

	// 加密命令
	var encCmd = &cobra.Command{
		Use:   "enc [pattern]",
		Short: "Encrypt files (supports wildcards)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			handleBatch(args[0], password, true, removeSource)
		},
	}

	// 解密命令
	var decCmd = &cobra.Command{
		Use:   "dec [pattern]",
		Short: "Decrypt files (supports wildcards)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			handleBatch(args[0], password, false, removeSource)
		},
	}

	rootCmd.AddCommand(encCmd, decCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// handleBatch 处理通配符匹配并循环调用处理函数
func handleBatch(pattern string, password string, encrypt bool, removeSource bool) {
	// 1. 解析通配符
	files, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Printf("Error: Invalid pattern: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No files matched the pattern.")
		return
	}

	for _, file := range files {
		// 跳过文件夹
		info, err := os.Stat(file)
		if err != nil || info.IsDir() {
			continue
		}

		// 2. 执行加解密
		err = processFile(file, password, encrypt, removeSource)
		if err != nil {
			fmt.Printf("[-] Failed [%s]: %v\n", file, err)
		} else {
			action := "Encrypted"
			if !encrypt {
				action = "Decrypted"
			}
			fmt.Printf("[+] %s: %s\n", action, file)
		}
	}
}

func processFile(filename string, password string, encrypt bool, removeSource bool) error {
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var newName string
	var out []byte

	if encrypt {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		out = gcm.Seal(nonce, nonce, data, nil)
		newName = filename + ".enc"
	} else {
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return fmt.Errorf("file too short")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decryption failed")
		}
		out = plaintext

		// 自动处理后缀
		if strings.HasSuffix(filename, ".enc") {
			newName = strings.TrimSuffix(filename, ".enc")
		} else {
			newName = "decrypted_" + filename
		}
	}

	// 写入新文件
	err = os.WriteFile(newName, out, 0644)
	if err != nil {
		return err
	}

	// 3. 如果设置了 -r 且新文件写入成功，则删除源文件
	if removeSource {
		_ = os.Remove(filename)
	}

	return nil
}
