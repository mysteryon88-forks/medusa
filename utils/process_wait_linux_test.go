package utils

import "testing"

func TestCommandGroupCertificateLinux(t *testing.T) {
	terminal, err := commandGroupCertificate(123)
	if terminal || err != nil {
		t.Fatalf("Linux must not certify the Darwin exception: %v, %v", terminal, err)
	}
}
