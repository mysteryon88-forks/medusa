//go:build !linux && !darwin && !windows

package utils

import "errors"

func validateCommandPlatform() error {
	return errors.New("cancellable process ownership is unsupported on this OS")
}
func waitCommandExit(int) error             { return validateCommandPlatform() }
func commandGroupRunning(int) (bool, error) { return false, validateCommandPlatform() }
