//go:build !windows

package utils

import (
	"errors"
	"syscall"
	"testing"
)

func TestCommandGroupSignalCertificate(t *testing.T) {
	preErr := errors.New("pre certificate failed")
	postErr := errors.New("post certificate failed")
	otherErr := errors.New("signal failed")
	type certificate struct {
		terminal bool
		err      error
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		for _, tc := range []struct {
			name         string
			pre, post    certificate
			signalErr    error
			wantErrs     []error
			notErr       error
			certificates int
		}{
			{"confirmed terminal", certificate{true, nil}, certificate{true, nil}, syscall.EPERM, nil, nil, 2},
			{"live before denial", certificate{false, nil}, certificate{true, nil}, syscall.EPERM, []error{syscall.EPERM}, nil, 1},
			{"pre failed", certificate{false, preErr}, certificate{true, nil}, syscall.EPERM, []error{syscall.EPERM, preErr}, nil, 1},
			{"not terminal afterward", certificate{true, nil}, certificate{false, nil}, syscall.EPERM, []error{syscall.EPERM}, nil, 2},
			{"post failed", certificate{true, nil}, certificate{false, postErr}, syscall.EPERM, []error{syscall.EPERM, postErr}, nil, 2},
			{"advisory failure and success", certificate{false, preErr}, certificate{}, nil, nil, preErr, 1},
			{"advisory failure and absent group", certificate{false, preErr}, certificate{}, syscall.ESRCH, []error{syscall.ESRCH}, preErr, 1},
			{"other signal error", certificate{true, nil}, certificate{true, nil}, otherErr, []error{otherErr}, nil, 1},
		} {
			t.Run(signal.String()+"/"+tc.name, func(t *testing.T) {
				checks := 0
				certify := func(group int) (bool, error) {
					if group != 123 {
						t.Errorf("certificate group = %d", group)
					}
					checks++
					if checks == 1 {
						return tc.pre.terminal, tc.pre.err
					}
					return tc.post.terminal, tc.post.err
				}
				calls := 0
				kill := func(group int, got syscall.Signal) error {
					calls++
					if group != -123 || got != signal {
						t.Errorf("signal = (%d, %v)", group, got)
					}
					return tc.signalErr
				}
				err := commandGroupSignal(123, signal, kill, certify)
				if len(tc.wantErrs) == 0 && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for _, want := range tc.wantErrs {
					if !errors.Is(err, want) {
						t.Errorf("error %v does not preserve %v", err, want)
					}
				}
				if tc.notErr != nil && errors.Is(err, tc.notErr) {
					t.Errorf("advisory error leaked: %v", err)
				}
				if calls != 1 || checks != tc.certificates {
					t.Errorf("calls=%d certificate checks=%d", calls, checks)
				}
			})
		}
	}
}

func TestCommandGroupSignalOrder(t *testing.T) {
	inspectionErr := errors.New("group inspection failed")
	for _, tc := range []struct {
		name                string
		termErr, inspectErr error
	}{
		{"stale negative scan", nil, nil},
		{"inspection and signal failure", syscall.EPERM, inspectionErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var signals []syscall.Signal
			kill := func(group int, signal syscall.Signal) error {
				if group != -123 {
					t.Errorf("signal group = %d", group)
				}
				signals = append(signals, signal)
				if signal == syscall.SIGTERM {
					return tc.termErr
				}
				return nil
			}
			inspections := 0
			inspect := func(group int) (bool, error) {
				inspections++
				if group != 123 {
					t.Errorf("inspection group = %d", group)
				}
				if inspections == 1 {
					return false, tc.inspectErr
				}
				return false, nil
			}
			err := cleanupCommandGroupWith(123, inspect, kill, func(int) (bool, error) { return false, nil })
			if len(signals) != 2 || signals[0] != syscall.SIGTERM || signals[1] != syscall.SIGKILL {
				t.Errorf("signal order: %v", signals)
			}
			for _, want := range []error{tc.termErr, tc.inspectErr} {
				if want != nil && !errors.Is(err, want) {
					t.Errorf("error %v does not preserve %v", err, want)
				}
			}
			if tc.termErr == nil && tc.inspectErr == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
