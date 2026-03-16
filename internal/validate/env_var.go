package validate

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// CredsB64EnvCheck returns a Check that validates an environment variable
// contains non-empty, valid base64-encoded NATS credentials.
func CredsB64EnvCheck(envName string) Check {
	return Check{
		Name: fmt.Sprintf("creds-b64-env %s", envName),
		Fn: func() error {
			return validateCredsB64Env(envName)
		},
	}
}

func validateCredsB64Env(envName string) error {
	value := os.Getenv(envName)
	if value == "" {
		return fmt.Errorf("environment variable %s is empty or not set", envName)
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("environment variable %s is not valid base64: %w", envName, err)
	}

	content := string(decoded)

	if !strings.Contains(content, jwtMarker) {
		return fmt.Errorf("decoded content missing %q section", jwtMarker)
	}

	return nil
}
