package validate

import "fmt"

// Check represents a single credential validation check.
type Check struct {
	Name string
	Fn   func() error
}

// RunAll executes all checks and returns the first error encountered.
func RunAll(checks []Check) error {
	for _, c := range checks {
		fmt.Printf("Checking: %s\n", c.Name)
		if err := c.Fn(); err != nil {
			fmt.Printf("FATAL: %s — %v\n", c.Name, err)
			return err
		}
		fmt.Printf("OK: %s\n", c.Name)
	}
	fmt.Println("All credential checks passed")
	return nil
}
