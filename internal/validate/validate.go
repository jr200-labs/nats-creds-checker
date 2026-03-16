package validate

import "go.uber.org/zap"

// Check represents a single credential validation check.
type Check struct {
	Name string
	Fn   func() error
}

// RunAll executes all checks and returns the first error encountered.
func RunAll(log *zap.Logger, checks []Check) error {
	for _, c := range checks {
		log.Info("checking", zap.String("check", c.Name))
		if err := c.Fn(); err != nil {
			log.Error("check failed", zap.String("check", c.Name), zap.Error(err))
			return err
		}
		log.Info("check passed", zap.String("check", c.Name))
	}
	log.Info("all credential checks passed")
	return nil
}
