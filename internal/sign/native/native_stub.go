//go:build !linux || !cgo

package native

import "errors"

const DefaultOffset uintptr = 0x5BD3EA1

type Config struct {
	Directory   string
	Offset      uintptr
	PreloadLibs []string
}

type Result struct {
	Token []byte
	Extra []byte
	Sign  []byte
}

type Signer struct{}

func New(Config) (*Signer, error) {
	return nil, errors.New("builtin signer requires linux with cgo enabled")
}

func (s *Signer) Sign(string, []byte, int) (*Result, error) {
	return nil, errors.New("builtin signer requires linux with cgo enabled")
}

func (s *Signer) Close() {}
