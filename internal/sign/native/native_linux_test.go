//go:build linux && cgo

package native

import (
	"os"
	"testing"
)

func TestSignSmoke(t *testing.T) {
	dir := os.Getenv("SIGN_WRAPPER_DIR")
	if dir == "" {
		t.Skip("SIGN_WRAPPER_DIR is not set")
	}

	signer, err := New(Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()

	result, err := signer.Sign("wtlogin.login", []byte{0x0b, 0x2d, 0x0e}, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token=%d extra=%d sign=%d", len(result.Token), len(result.Extra), len(result.Sign))
}
