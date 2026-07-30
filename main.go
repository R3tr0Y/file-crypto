package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var password string
	var removeSource bool
	var recursive bool
	var all bool

	var rootCmd = &cobra.Command{
		Use:   "fcrypt",
		Short: "A simple file encryption/decryption tool",
		Long:  `fcrypt is a lightweight CLI tool to encrypt and decrypt files using AES-256-GCM. Supports wildcards like *.txt`,
	}

	rootCmd.PersistentFlags().StringVarP(&password, "pass", "p", "", "Password for encryption/decryption")
	rootCmd.PersistentFlags().BoolVarP(&removeSource, "remove", "r", false, "Remove source file after successful processing")
	rootCmd.PersistentFlags().BoolVarP(&recursive, "recursive", "R", false, "Recursively traverse subdirectories")
	rootCmd.PersistentFlags().BoolVarP(&all, "all", "a", false, "Process all files in directory (encrypt: skip .enc; decrypt: only .enc)")
	rootCmd.MarkPersistentFlagRequired("pass")

	var encCmd = &cobra.Command{
		Use:   "enc <files|dirs|patterns>...",
		Short: "Encrypt files (supports wildcards, multiple targets)",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			handleCommand(args, password, true, removeSource, recursive, all)
		},
	}

	var decCmd = &cobra.Command{
		Use:   "dec <files|dirs|patterns>...",
		Short: "Decrypt files (supports wildcards, multiple targets)",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			handleCommand(args, password, false, removeSource, recursive, all)
		},
	}

	rootCmd.AddCommand(encCmd, decCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleCommand(args []string, password string, encrypt, removeSource, recursive, all bool) {
	var files []string

	for _, arg := range args {
		info, err := os.Stat(arg)

		if err == nil && info.IsDir() {
			if !all {
				fmt.Printf("Error: '%s' is a directory, use -a to process all files\n", arg)
				continue
			}
			files = append(files, collectDirFiles(arg, recursive, encrypt)...)
		} else if hasGlobChars(arg) {
			if recursive {
				files = append(files, recursiveGlob(arg)...)
			} else {
				matched, gerr := filepath.Glob(arg)
				if gerr != nil {
					fmt.Printf("Error: invalid pattern '%s': %v\n", arg, gerr)
					continue
				}
				for _, f := range matched {
					if fi, e := os.Stat(f); e == nil && !fi.IsDir() {
						files = append(files, f)
					}
				}
			}
		} else {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Println("No matching files found.")
		return
	}

	for _, file := range files {
		err := processFile(file, password, encrypt, removeSource)
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

func hasGlobChars(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func recursiveGlob(pattern string) []string {
	pattern = filepath.FromSlash(pattern)
	root := filepath.Dir(pattern)
	if root == "" {
		root = "."
	}

	dirPart := filepath.Dir(pattern)
	basePart := filepath.Base(pattern)

	var files []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		matched, _ := filepath.Match(basePart, d.Name())
		if !matched {
			return nil
		}

		if dirPart != "." && dirPart != "" {
			prefix := dirPart + string(filepath.Separator)
			if !strings.HasPrefix(p, prefix) && p != dirPart {
				return nil
			}
		}

		files = append(files, p)
		return nil
	})
	return files
}

func collectDirFiles(root string, recursive bool, encrypt bool) []string {
	var files []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if !recursive && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if encrypt && strings.HasSuffix(p, ".enc") {
			return nil
		}
		if !encrypt && !strings.HasSuffix(p, ".enc") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	return files
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
