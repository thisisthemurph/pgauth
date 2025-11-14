package types

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
)

type UserResponse struct {
	ID        uuid.UUID       `json:"id"`
	Email     string          `json:"email"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	DeletedAt *time.Time      `json:"deleted_at"`
	IsDeleted bool            `json:"is_deleted"`
}

func NewUserResponse(u userrepo.AuthUser) *UserResponse {
	var deletedAt *time.Time
	if u.DeletedAt.Valid {
		deletedAt = &u.DeletedAt.Time
	}

	return &UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Data:      u.UserData,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		DeletedAt: deletedAt,
		IsDeleted: deletedAt != nil,
	}
}
