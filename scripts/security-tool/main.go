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
	key := flag.String("key", "", "Base64 encoded private key for signing")
	flag.Parse()

	if *gen {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Public Key (Base64): %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("Private Key (Base64): %s\n", base64.StdEncoding.EncodeToString(priv))
		return
	}

	if *sign != "" {
		if *key == "" {
			log.Fatal("-key required for signing")
		}
		privBytes, err := base64.StdEncoding.DecodeString(*key)
		if err != nil {
			log.Fatal("Invalid private key encoding")
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
