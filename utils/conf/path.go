package conf

import (
	"os"
	"path/filepath"
	"runtime"
)

// AppSrcPath 源码根目录
var AppSrcPath string

// AppPath 二进制文件根目录
var AppPath string

func init() {
	_, file, _, _ := runtime.Caller(0)
	upDir := ".." + string(filepath.Separator)
	var err error
	if AppSrcPath, err = filepath.Abs(filepath.Dir(filepath.Join(file, upDir, upDir))); err != nil {
		panic(err)
	}

	if AppPath, err = filepath.Abs(filepath.Dir(os.Args[0])); err != nil {
		panic(err)
	}
}
