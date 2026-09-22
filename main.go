package main

import (
	"fmt"

	"github.com/mazhar266/Quanto-Vault/internal/vault"
)

func main() {
	svc := vault.NewService()
	fmt.Printf("Quanto-Vault initialized with key auth support (default: %s)\n", vault.KeyTypeEd25519)
	_ = svc
}
