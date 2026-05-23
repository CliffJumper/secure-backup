package main

import (
"crypto/ed25519"
"crypto/rand"
"encoding/base64"
"flag"
"fmt"
"log"
"os"
)

func main() {
	gen := flag.Bool("gen", false, "Generate a new keypair")
	sign := flag.String("sign", "", "Sign a file with a private key")
	keyFile := flag.String("key", "", "Path to base64-encoded private key file for signing")
	exportKey := flag.String("exportkey", "", "Export private key to file (only when generating)")
	flag.Parse()

	if *gen {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		pubB64 := base64.StdEncoding.EncodeToString(pub)
		privB64 := base64.StdEncoding.EncodeToString(priv)

		if *exportKey != "" {
			pubFile := *exportKey
			privFile := pubFile + ".priv"
			if err := os.WriteFile(pubFile, []byte(pubB64), 0600); err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(privFile, []byte(privB64), 0600); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Public key written to %s (0600)\n", pubFile)
			fmt.Printf("Private key written to %s (0600)\n", privFile)
			return
		}
		fmt.Printf("Public Key (Base64): %s\n", pubB64)
		fmt.Printf("Private Key (Base64): %s\n", privB64)
		return
	}

	if *sign != "" {
		if *keyFile == "" {
			log.Fatal("-key required (path to base64-encoded key file)")
		}
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal("Failed to read key file")
		}
		privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
		if err != nil {
			log.Fatal("Invalid private key encoding in key file")
		}
		if len(privBytes) != ed25519.PrivateKeySize {
			log.Fatal("Invalid private key size")
		}

		data, err := os.ReadFile(*sign)
		if err != nil {
			log.Fatal(err)
		}

		sig := ed25519.Sign(privBytes, data)
		sigPath := *sign + ".sig"
		if err := os.WriteFile(sigPath, sig, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Signed %s -> %s\n", *sign, sigPath)
		return
	}

	flag.Usage()
}
