//go:build !(linux && amd64)

package inject

import "errors"

type caller struct{}

func borrow(int, *Result, func(*caller) error) error {
	return errors.New("-inject is implemented for linux/amd64 only")
}

func (*caller) libcSym(...string) (uint64, error)      { return 0, nil }
func (*caller) libmhpSym(string) (uint64, error)       { return 0, nil }
func (*caller) str(string) (uint64, error)             { return 0, nil }
func (*caller) call(uint64, ...uint64) (uint64, error) { return 0, nil }
func (*caller) dlerror() string                        { return "" }
