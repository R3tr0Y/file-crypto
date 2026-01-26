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

	// 根命令
	var rootCmd = &cobra.Command{
		Use:   "fcypt",
		Short: "一个简单的文件加解密工具",
	}

	// 持久化 Flag（所有子命令通用）
	rootCmd.PersistentFlags().StringVarP(&password, "pass", "p", "", "用于加密的密码")
	rootCmd.MarkPersistentFlagRequired("pass")

	// 加密子命令
	var encCmd = &cobra.Command{
		Use:   "enc [file]",
		Short: "加密一个文件",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			processFile(args[0], password, true)
		},
	}

	// 解密子命令
	var decCmd = &cobra.Command{
		Use:   "dec [file]",
		Short: "解密一个文件",
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

// processFile 处理文件读写逻辑
func processFile(filename string, password string, encrypt bool) {
	// 使用 SHA256 将任意长度密码转换为 32 字节 Key (AES-256)
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("错误: 无法读取文件: %v\n", err)
		return
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	if encrypt {
		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		// 密文 = nonce + 实际加密内容
		out := gcm.Seal(nonce, nonce, data, nil)
		newName := filename + ".enc"
		os.WriteFile(newName, out, 0644)
		fmt.Printf("成功！文件已加密为: %s\n", newName)
	} else {
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			fmt.Println("错误: 文件格式不正确")
			return
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Println("解密失败: 密码错误或数据损坏")
			return
		}
		// 简单处理：解密后尝试移除 .enc 后缀
		newName := "decrypted_" + filename
		os.WriteFile(newName, plaintext, 0644)
		fmt.Printf("成功！文件已解密为: %s\n", newName)
	}
}
