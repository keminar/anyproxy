package trace

import "fmt"

// ID 日志ID。用方括号包成一个 token, 避免行首 "ID #34," 的尾逗号被编辑器/工具当成 CSV 列。
func ID(id uint) string {
	return fmt.Sprintf("[ID #%d]", id)
}
