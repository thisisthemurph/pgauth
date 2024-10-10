package crypt

import (
	"crypto/rand"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"math/big"
)

func HashValue(v string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyHash(hash, v string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(v))
	return err == nil
}

func GenerateToken() string {
	return uuid.New().String()
}

func GenerateOTP() (string, error) {
	otp := ""
	for _ = range 6 {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp += fmt.Sprintf("%d", num)
	}
	return otp, nil
}
