package logger_test

import (
	"log"
	"strings"
	"testing"

	"credhub_setup/pkg/logger"

	"github.com/stretchr/testify/assert"
)

func TestLogAdapter(t *testing.T) {
	t.Parallel()

	builder := strings.Builder{}
	baseLogger := log.New(&builder, "", 0)
	adapter := logger.NewAdapter(baseLogger)
	adapter.Log("this", " ", "is", " ", "plain", " ", "log")
	adapter.Logf("this is %s log", "formatted")
	result := builder.String()
	expected := "this is plain log\nthis is formatted log\n"
	assert.Equal(t, expected, result)
}
