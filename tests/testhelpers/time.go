package testhelpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func mustParseTime(t *testing.T, s string) time.Time {
	layout := "2006-01-02 15:04:05"
	parsedTime, err := time.Parse(layout, s)
	assert.NoError(t, err)
	return parsedTime.UTC()
}

func AssertTimeMatchesString(t *testing.T, expectedString string, actialTime time.Time) {
	expected := mustParseTime(t, expectedString).UTC()
	assert.Equal(t, expected, actialTime.UTC())
}
