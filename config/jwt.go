package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/faridlan/jwt-go/model"
	"github.com/golang-jwt/jwt/v5"
)

func LoadPrivateKey(filePath string) (*ecdsa.PrivateKey, error) {

	keyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %v", err)
	}

	return privateKey, nil

}

func GenerateJWT(claim *model.Claim) (string, error) {

	claim.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute * 10))

	privateKey, err := LoadPrivateKey("./private.pem")
	if err != nil {
		return "", fmt.Errorf("failed to load private key : %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claim)
	return token.SignedString(privateKey)

}

func GenerateAndStorePrivateKey(filePath string) (*ecdsa.PrivateKey, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key : %v", err)
	}

	derStream, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key to DER: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derStream,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return nil, errors.New("failed to encode private key to PEM format")
	}

	err = os.WriteFile(filePath, pemBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key to file: %v", err)
	}

	return privateKey, nil

}
