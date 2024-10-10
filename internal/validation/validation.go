package validation

import (
	"fmt"
	"net/mail"
)

func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func ValidatePasswordFactory(minLen int) func(string) error {
	return func(password string) error {
		if len(password) < minLen {
			return fmt.Errorf("password must be at least %d characters long", minLen)
		}
		return nil
	}
}
