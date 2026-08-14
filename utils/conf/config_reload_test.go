package conf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNotifyReloadOnAtomicSave 验证「写临时文件再 rename 覆盖」的原子保存(Linux 上
// vim/VSCode/sed -i 的默认行为)能触发配置重载。旧实现直接 watch 文件, rename 会替换
// inode 使 watch 失效且收不到 Write 事件, 因此不会重载; 改为 watch 目录后应能捕获。
func TestNotifyReloadOnAtomicSave(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "router.yaml")
	if err := os.WriteFile(cfgPath, []byte("listen: \"3000\"\nwatcher: true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 先按正常流程加载一次
	conf, err := LoadRouterConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	RouterConfig = &conf
	if RouterConfig.Listen != "3000" {
		t.Fatalf("initial listen = %q, want 3000", RouterConfig.Listen)
	}

	go notify(cfgPath)
	// 等待 watcher.Add(dir) 生效
	time.Sleep(300 * time.Millisecond)

	// 原子保存: 写临时文件后 rename 覆盖(替换 inode)
	tmp := filepath.Join(dir, ".router.yaml.tmp")
	if err := os.WriteFile(tmp, []byte("listen: \"4000\"\nwatcher: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		t.Fatal(err)
	}

	// 防抖 200ms + 事件延迟, 轮询等待重载生效
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if RouterConfig.Listen == "4000" {
			return // 重载成功
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("config not reloaded after atomic save: listen = %q, want 4000", RouterConfig.Listen)
}
