package validate

import (
	"fmt"
	"os"
	"path/filepath"
)

// MultiFileCheck returns a Check that validates a directory contains
// all expected credential and key files.
//
// expect: filenames that must be valid .creds files (checked for JWT + NKEY markers)
// expectFiles: filenames that must exist and be non-empty
func MultiFileCheck(dir string, expect []string, expectFiles []string) Check {
	return Check{
		Name: fmt.Sprintf("creds-dir %s", dir),
		Fn: func() error {
			return validateMultiFile(dir, expect, expectFiles)
		},
	}
}

func validateMultiFile(dir string, expect []string, expectFiles []string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot access directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	for _, name := range expect {
		path := filepath.Join(dir, name)
		fmt.Printf("  Checking creds: %s\n", name)
		if err := validateCredsFile(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	for _, name := range expectFiles {
		path := filepath.Join(dir, name)
		fmt.Printf("  Checking file: %s\n", name)
		if err := validateFileExists(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	return nil
}

func validateFileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	return nil
}
