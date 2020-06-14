package trace

import "fmt"

// ID 日志ID
func ID(id uint) string {
	return fmt.Sprintf("ID #%d,", id)
}
