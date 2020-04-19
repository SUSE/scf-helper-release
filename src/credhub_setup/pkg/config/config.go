package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"

	"credhub_setup/pkg/logger"
)

// UAA contains UAA-related configuration options.
type UAA struct {
	OAuthClient string `env:"OAUTH_CLIENT"  helpText:"UAA_OAuth client ID"`
	OAuthSecret string `env:"OAUTH_SECRET"  helpText:"UAA OAuth client secret"`
	UAATokenURL string `env:"UAA_TOKEN_URL" helpText:"UAA token endpoint URL"`
	UAACACert   string `env:"UAA_CA_CERT"   helpText:"Path to UAA CA certificate file"`
}

// CC contains cloud controller-related configuration options.
type CC struct {
	CCURL    string `env:"CC_URL"     helpText:"Cloud controller endpoint URL"`
	CCCACert string `env:"CC_CA_CERT" helpText:"Path to cloud controller CA certificate file"`
	Name     string `env:"POD_NAME"   helpText:"Name of the pod to create the rule for"`
	PodIP    string `env:"POD_IP"     helpText:"IP address of the pod to apply to the security group"`
	Ports    string `env:"PORTS"      helpText:"Ports to expose in the security group"`
}

// Config is a union of all the configuration options available.
type Config struct {
	UAA
	CC
	WaitDuration time.Duration
}

// collectConfig examines the passed-in value (which must be a Struct) and
// populates it with the appropriate configuration options, where each item is
// fetched via the given lookupFunc.  It returns the names of the fields that
// were not set.
func collectConfig(value reflect.Value, lookupFunc func(string) (string, bool)) []string {
	// Dereference value if it's a pointer (i.e. the top level)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	// Get the value's type, so we can examine its field tags.
	typ := value.Type()
	if typ.Kind() != reflect.Struct {
		panic(fmt.Errorf("unexpected value type %v", typ.Kind()))
	}
	var missingEnvs []string
	for index := 0; index < typ.NumField(); index++ {
		child := value.Field(index)
		field := typ.Field(index)
		switch field.Type.Kind() {
		case reflect.Struct:
			innerMissingEnvs := collectConfig(child, lookupFunc)
			missingEnvs = append(missingEnvs, innerMissingEnvs...)
		case reflect.String:
			envName := field.Tag.Get("env")
			envValue, ok := lookupFunc(envName)
			if ok {
				child.SetString(envValue)
			} else {
				missingEnvs = append(missingEnvs, envName)
			}
		default:
			if _, ok := field.Tag.Lookup("env"); ok {
				panic(fmt.Errorf("invalid field %s: not a string", field.Name))
			}
		}
	}
	return missingEnvs
}

// Load returns a populated Config with the appropriate configuration options,
// where each item is fetched via the given lookupFunc.
func Load(lookupFunc func(string) (string, bool)) (Config, error) {
	c := Config{WaitDuration: 10 * time.Second}
	missingEnvs := collectConfig(reflect.ValueOf(&c), lookupFunc)

	if len(missingEnvs) > 0 {
		sort.Strings(missingEnvs)
		return Config{}, fmt.Errorf("missing required environment variables: %v", missingEnvs)
	}

	return c, nil
}

// collectHelp recusively inspects a type for help information, and returns the
// environment variables and their help text.
func collectHelp(t reflect.Type) ([]string, []string) {
	var names, helpTexts []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		switch field.Type.Kind() {
		case reflect.Struct:
			innerNames, innerHelpTexts := collectHelp(field.Type)
			names = append(names, innerNames...)
			helpTexts = append(helpTexts, innerHelpTexts...)
		default:
			names = append(names, field.Tag.Get("env"))
			helpTexts = append(helpTexts, field.Tag.Get("helpText"))
		}
	}
	return names, helpTexts
}

func maxStringLength(inputs []string) int {
	maxLength := 0
	for _, input := range inputs {
		if len(input) > maxLength {
			maxLength = len(input)
		}
	}
	return maxLength
}

func ShowHelp(l logger.Logger) {
	l.Logf("%s <post-start|drain>\n", os.Args[0])
	l.Logf("\n")
	l.Logf("Required evnironment variables:\n")
	names, helpTexts := collectHelp(reflect.TypeOf(Config{}))
	nameLength := maxStringLength(names)
	helpTextLength := maxStringLength(helpTexts)
	for i := 0; i < len(names); i++ {
		l.Logf("    %-*s    %-*s\n",
			nameLength, names[i],
			helpTextLength, helpTexts[i])
	}
}
