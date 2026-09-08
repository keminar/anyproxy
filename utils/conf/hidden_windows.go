package conf

import "syscall"

// hideFile 给文件打上 Windows 的隐藏属性。
//
// 点前缀(.router.uuid)在 unix 上就等于隐藏, 但 Windows 的资源管理器/dir 照样列出来,
// 得靠文件属性。尽力而为: 失败只意味着文件在资源管理器里看得见, 不影响功能, 没必要
// 为此让加载配置失败。
func hideFile(path string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = syscall.SetFileAttributes(p, syscall.FILE_ATTRIBUTE_HIDDEN)
}
