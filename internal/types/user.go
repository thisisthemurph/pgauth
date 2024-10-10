package types

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                         uuid.UUID  `json:"id"`
	Email                      string     `json:"email"`
	EncryptedPassword          string     `json:"-"`
	EmailConfirmedAt           *time.Time `json:"email_confirmed_at"`
	ConfirmationToken          string     `json:"confirmation_token"`
	ConfirmationTokenCreatedAt *time.Time `json:"confirmation_token_created_at"`
	EmailChange                string     `json:"email_change"`
	EmailChangeToken           string     `json:"-"`
	EmailChangeRequestedAt     *time.Time `json:"email_change_sent_at"`
	PasswordChange             string     `json:"password_change"`
	PasswordChangeToken        string     `json:"-"`
	PasswordChangeRequestedAt  *time.Time `json:"password_change_sent_at"`
	EncryptedOTP               string     `json:"encrypted_otp"`
	OTPCreatedAt               *time.Time `json:"otp_created_at"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	DeletedAt                  *time.Time `json:"deleted_at"`
}

func MapRowToUser(row *sql.Row) (*User, error) {
	var u User
	var confirmationToken *string
	var emailChange *string
	var emailChangeToken *string
	var passwordChange *string
	var passwordChangeToken *string
	var encryptedOTP *string

	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.EncryptedPassword,
		&u.EmailConfirmedAt,
		&confirmationToken,
		&u.ConfirmationTokenCreatedAt,
		&emailChange,
		&emailChangeToken,
		&u.EmailChangeRequestedAt,
		&passwordChange,
		&passwordChangeToken,
		&u.PasswordChangeRequestedAt,
		&encryptedOTP,
		&u.OTPCreatedAt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	u.ConfirmationToken = ptrToRef(confirmationToken)
	u.EmailChange = ptrToRef(emailChange)
	u.EmailChangeToken = ptrToRef(emailChangeToken)
	u.PasswordChange = ptrToRef(passwordChange)
	u.PasswordChangeToken = ptrToRef(passwordChangeToken)
	u.EncryptedOTP = ptrToRef(encryptedOTP)

	return &u, nil
}

// ptrToRef returns the dereferenced value of a pointer to T.
// If the pointer is nil, it returns the default value of T.
func ptrToRef[T comparable](v *T) T {
	if v == nil {
		var defaultValue T
		return defaultValue
	}
	return *v
}
