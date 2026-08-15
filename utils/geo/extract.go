package geo

import (
	"fmt"
	"os"
	"strings"
)

// Extract 从 geoip.dat / geosite.dat 中提取指定类别, 写出一个精简的同格式 .dat。
//
// 在 wire 层做, 不区分 geoip 还是 geosite: 两者外层都是
// `message List { repeated Entry entry = 1 }`, 且 Entry 的字段1(string)是类别码。
// 匹配类别码后整块拷贝该 Entry 的原始字节, 无需理解内部 CIDR/Domain 结构。
//
// 供离线用命令参数生成小文件(随发布携带), 运行时只读小文件。
func Extract(inPath string, cats []string, outPath string) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(cats))
	for _, c := range cats {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" {
			want[c] = true
		}
	}
	if len(want) == 0 {
		return fmt.Errorf("未指定要提取的类别")
	}

	var out []byte
	got := map[string]bool{}
	ok := eachField(data, func(f wireField) {
		if f.num != 1 || f.wire != 2 { // repeated Entry entry = 1
			return
		}
		code := strings.ToLower(entryCode(f.data))
		if !want[code] {
			return
		}
		got[code] = true
		// 重新以 field1(wire2) 写出: tag 0x0A + varint(len) + 原始 Entry 字节
		out = append(out, 0x0A)
		out = appendVarint(out, uint64(len(f.data)))
		out = append(out, f.data...)
	})
	if !ok {
		return fmt.Errorf("解析 %s 失败(非法 protobuf 或非 geoip/geosite .dat)", inPath)
	}

	var missing []string
	for c := range want {
		if !got[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s 中找不到类别: %s", inPath, strings.Join(missing, ", "))
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return err
	}
	return nil
}

// appendVarint 追加一个 base-128 varint。
func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
