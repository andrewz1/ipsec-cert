package xt

import (
	"os"
	"path/filepath"
)

func CheckFile(name string) bool {
	if st, err := os.Stat(name); err == nil {
		return !st.IsDir()
	}
	return false
}

func MakeDirsForFile(name string) error {
	name = filepath.Clean(name)
	dir := filepath.Dir(name)
	if dir == "." || dir == "" || dir == string(filepath.Separator) {
		return nil
	}
	return os.MkdirAll(dir, 0775)
}
