package null

import (
	"database/sql"

	"github.com/google/uuid"
)

func ValidString(s string) sql.NullString {
	return sql.NullString{
		Valid:  true,
		String: s,
	}
}

func ValidUUID(u uuid.UUID) uuid.NullUUID {
	return uuid.NullUUID{
		Valid: true,
		UUID:  u,
	}
}
