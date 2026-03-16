package validate

import (
	"fmt"
	"os"
	"strings"
)

const (
	jwtMarker  = "BEGIN NATS USER JWT"
	nkeyMarker = "BEGIN USER NKEY SEED"
)

// CredsFileCheck returns a Check that validates a .creds file exists,
// is non-empty, and contains the expected NATS JWT and NKEY markers.
func CredsFileCheck(path string) Check {
	return Check{
		Name: fmt.Sprintf("creds-file %s", path),
		Fn: func() error {
			return validateCredsFile(path)
		},
	}
}

func validateCredsFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("file is empty")
	}

	content := string(data)

	if !strings.Contains(content, jwtMarker) {
		return fmt.Errorf("missing %q section", jwtMarker)
	}

	if !strings.Contains(content, nkeyMarker) {
		return fmt.Errorf("missing %q section", nkeyMarker)
	}

	return nil
}
