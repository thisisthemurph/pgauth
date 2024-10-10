package crypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOTP()
	assert.NoError(t, err)
	assert.Len(t, otp, 6)
}
