package pgauth

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
)

// User represents an authenticated user in the system.
// It contains basic user information and metadata about their account status.
type User struct {
	// ID is the unique identifier for the user.
	ID uuid.UUID `json:"id"`

	// Email is the user's email address, used for authentication and identification.
	Email string `json:"email"`

	// Data contains additional user-defined data stored as JSON.
	// This can be used to store custom user attributes.
	Data json.RawMessage `json:"data"`

	// CreatedAt is the timestamp when the user account was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the user account was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// DeletedAt is the timestamp when the user account was soft-deleted.
	// It will be nil if the user has not been deleted.
	DeletedAt *time.Time `json:"deleted_at"`

	// IsDeleted indicates whether the user account has been soft-deleted.
	IsDeleted bool `json:"is_deleted"`
}

// NewUser creates a User from a repository AuthUser.
func NewUser(u userrepo.AuthUser) *User {
	var deletedAt *time.Time
	if u.DeletedAt.Valid {
		deletedAt = &u.DeletedAt.Time
	}

	return &User{
		ID:        u.ID,
		Email:     u.Email,
		Data:      u.UserData,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		DeletedAt: deletedAt,
		IsDeleted: deletedAt != nil,
	}
}
