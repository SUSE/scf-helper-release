package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"

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

// Resolver contains DNS resolver-related configuration options.
type Resolver struct {
	DNSServer string `env:"DNS_SERVER"         helpText:"DNS server to use to look up KubeCF hosts"`
}

// Config is a union of all the configuration options available.
type Config struct {
	UAA
	CC
	Resolver
}

// Load returns a populated Config with the appropriate configuration options,
// where each item is fetched via the given lookupFunc.
func Load(lookupFunc func(string) (string, bool)) (Config, error) {
	var missingEnvs []string
	c := Config{}
	topValue := reflect.ValueOf(&c)
	topType := topValue.Type().Elem()
	for topIndex := 0; topIndex < topType.NumField(); topIndex++ {
		topField := topType.Field(topIndex)
		if !topField.Anonymous {
			panic(fmt.Sprintf("Config struct has top level non-anonymous field %s", topField.Name))
		}
		innerType := topField.Type
		for innerIndex := 0; innerIndex < innerType.NumField(); innerIndex++ {
			innerField := innerType.Field(innerIndex)
			envName := innerField.Tag.Get("env")
			envValue, ok := lookupFunc(envName)
			if !ok {
				missingEnvs = append(missingEnvs, envName)
				continue
			}
			topValue.Elem().Field(topIndex).Field(innerIndex).SetString(envValue)
		}
	}

	if len(missingEnvs) > 0 {
		sort.Strings(missingEnvs)
		return Config{}, fmt.Errorf("missing required environment variables: %v", missingEnvs)
	}

	return c, nil
}

// collectHelp recusively inspects a type for help information, and returns the
// environment variables and their help text, plus the maximum length of each.
func collectHelp(t reflect.Type) ([]string, int, []string, int) {
	var nameLength, helpTextLength int
	var names, helpTexts []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			innerNames, innerNameLength, innerHelpTexts, innerHelpTextLength := collectHelp(field.Type)
			names = append(names, innerNames...)
			if innerNameLength > nameLength {
				nameLength = innerNameLength
			}
			helpTexts = append(helpTexts, innerHelpTexts...)
			if innerHelpTextLength > helpTextLength {
				helpTextLength = innerHelpTextLength
			}
			continue
		}
		name := field.Tag.Get("env")
		names = append(names, name)
		if len(name) > nameLength {
			nameLength = len(name)
		}
		helpText := field.Tag.Get("helpText")
		helpTexts = append(helpTexts, helpText)
		if len(helpText) > helpTextLength {
			helpTextLength = len(helpText)
		}
	}
	return names, nameLength, helpTexts, helpTextLength
}

func ShowHelp(l logger.Logger) {
	l.Logf("%s <post-start|drain>\n", os.Args[0])
	l.Logf("\n")
	l.Logf("Required evnironment variables:\n")
	names, nameLength, helpTexts, helpTextLength := collectHelp(reflect.TypeOf(Config{}))
	for i := 0; i < len(names); i++ {
		l.Logf("    %-*s    %-*s\n",
			nameLength, names[i],
			helpTextLength, helpTexts[i])
	}
}
