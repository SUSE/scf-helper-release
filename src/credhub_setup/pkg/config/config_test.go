package config

import (
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"credhub_setup/pkg/logger"
)

func TestLoad(t *testing.T) {
	t.Run("with missing entries", func(t *testing.T) {
		var missingEnvs []string
		lookup := func(key string) (string, bool) {
			// If the string is even length, pretend it's unset.
			// Otherwise, return the string as-is.
			if len(key)%2 == 0 {
				missingEnvs = append(missingEnvs, key)
				return "", false
			}
			return key, true
		}
		_, err := Load(lookup)
		assert.Error(t, err, "expected errors loading configs")
		sort.Strings(missingEnvs)
		assert.Contains(t, err.Error(), fmt.Sprintf("%v", missingEnvs),
			"error messsage should contain missing variables")
	})

	t.Run("with all variables given", func(t *testing.T) {
		expected := Config{
			UAA: UAA{
				OAuthClient: "OAUTH_CLIENT",
				OAuthSecret: "OAUTH_SECRET",
				UAATokenURL: "UAA_TOKEN_URL",
				UAACACert:   "UAA_CA_CERT",
			},
			CC: CC{
				CCURL:    "CC_URL",
				CCCACert: "CC_CA_CERT",
				Name:     "POD_NAME",
				PodIP:    "POD_IP",
				Ports:    "PORTS",
			},
			Resolver: Resolver{
				DNSServer: "DNS_SERVER",
			},
		}
		lookup := func(key string) (string, bool) {
			return key, true
		}
		actual, err := Load(lookup)
		assert.NoError(t, err, "unexpected error loading configs")
		assert.Equal(t, expected, actual, "unexpected configs loaded")
	})
}

func TestCollectHelp(t *testing.T) {
	// collectHelp doesn't actually hard code a type, so we can test it with a
	// custom one.
	var dummy struct {
		topField string `env:"TOP_FIELD" helpText:"top field"`
		inner    struct {
			innerField string `env:"INNER_FIELD" helpText:"inner field"`
		}
	}
	expectedNames := []string{"TOP_FIELD", "INNER_FIELD"}
	expectedHelpTexts := []string{"top field", "inner field"}
	names, helpTexts := collectHelp(reflect.TypeOf(dummy))
	assert.Equal(t, expectedNames, names, "got unexpected names")
	assert.Equal(t, expectedHelpTexts, helpTexts, "got unexpected help texts")
}

func TestMaxStringLength(t *testing.T) {
	assert.Equal(t, 0, maxStringLength([]string{}))
	assert.Equal(t, 5, maxStringLength([]string{"hello"}))
	assert.Equal(t, 8, maxStringLength([]string{"multiple", "strings"}))
	assert.Equal(t, 7, maxStringLength([]string{"start", "shorter"}))
}

func TestShowHelp(t *testing.T) {
	builder := strings.Builder{}
	baseLogger := log.New(&builder, "", 0)
	adapter := logger.NewAdapter(baseLogger)
	ShowHelp(adapter)
	result := builder.String()
	var paramLines []string
	for _, line := range strings.Split(result, "\n") {
		if strings.HasPrefix(line, " ") {
			paramLines = append(paramLines, line)
		}
	}
	names, helpTexts := collectHelp(reflect.TypeOf(Config{}))
	if assert.Len(t, paramLines, len(names), "unexpected number of parameter lines") {
		for i, line := range paramLines {
			assert.Contains(t, line, names[i])
			assert.Contains(t, line, helpTexts[i])
		}
	}
}
