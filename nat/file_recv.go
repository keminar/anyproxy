package nat

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/conf"
)

// splitRecvSpec 拆 "-recv" 参数: scp 风格的 email:path, 冒号后面是要从对端取什么。
//
// 与 -send 的 -to 拆法(splitSendTo)对称, 但这里的路径是**必需的**: -send 的子目录
// 不给就是"放到收方目录根下", 有个说得通的默认值; 取文件不给路径却没有安全的默认
// —— 猜"整个目录"等于一句话把对方的共享目录全端过来, 这不该是手滑的后果。
func splitRecvSpec(recv string) (email, remotePath string, err error) {
	idx := strings.IndexByte(recv, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("-recv %s does not say what to fetch, use -recv EMAIL:PATH (e.g. -recv %s:backup)", recv, recv)
	}
	email = recv[:idx]
	raw := strings.Trim(recv[idx+1:], "/")
	if raw == "" {
		return "", "", fmt.Errorf("-recv %s has an empty path after the colon, use -recv EMAIL:PATH", recv)
	}
	// 与 splitSendTo 同一套校验: 反斜杠/冒号在两端的含义不一致, .. 会跑出共享目录。
	// 对端也会自己再查一遍(见 resolveShared), 这里挡住只是为了当场就把话说清楚。
	if strings.ContainsAny(raw, `\:`) {
		return "", "", fmt.Errorf("-recv path %q must not contain backslash or colon", raw)
	}
	clean := path.Clean(raw)
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", "", fmt.Errorf("-recv path %q escapes the peer's shared directory", raw)
		}
	}
	if clean == "." {
		return "", "", fmt.Errorf("-recv path %q resolves to nothing", raw)
	}
	return email, clean, nil
}

// RecvFiles 从另一个订阅方取文件, 是 -send 的反向操作: 人在本机操作, 对端不需要有人
// 配合跑命令。建 websocket -> 找到对端 -> 要一份清单 -> 逐个取回落盘 -> 退出。跟
// -send 一样是独立进程, 不要求本机常驻着 anyproxy。
//
// 安全边界在对端那侧, 不在这里: 本机必须已经配在对方的 websocket.client.receive.allow
// 里(email + uuid), 且只能取到对方 receive.dir 之内的东西。也就是说"允许某人给我发
// 文件"现在同时意味着"允许他读我这个目录"——沿用同一份配置是有意的(一个对称的动作
// 不值得维护两份几乎一样的名单), 但这个含义在 conf/router.yaml 和文档里都写明了。
//
// via 与 -send 对称, 且是硬限制而不是提示: 选 direct 就打洞直连、打不通直接失败,
// 选 relay 就经服务端 B 中继。注意中继取件要求 B 也升级到本版本(见 FileRelayOpen.Op)。
//
// to 是本地存放目录, 与 -send 的 -to 共用同一个命令行参数、按场景解释成不同的东西:
// -send 时是"发给谁", -recv 时是"存哪儿"。留空则存到当前目录。
//
// parallel 与 SendFiles 同一个参数、同一个阈值判断(见 planChunks): 单个文件够大时
// 按 e.Size(清单里已经有, 不用额外问一次)切块, 各开一条独立连接并行取。
func RecvFiles(cfg conf.WsClient, recv, to, via string, parallel int) error {
	if cfg.Connect == "" {
		return fmt.Errorf("websocket.client.connect is empty, cannot reach the server")
	}
	if recv == "" {
		return fmt.Errorf("-recv is required: whose files to fetch and which ones, e.g. -recv a@example.com:backup")
	}
	from, remotePath, err := splitRecvSpec(recv)
	if err != nil {
		return err
	}
	if from == "" {
		return fmt.Errorf("-recv %s has an empty email, use -recv EMAIL:PATH", recv)
	}
	if from == cfg.Email {
		return fmt.Errorf("-recv %s is this machine's own email", from)
	}
	if via != ViaDirect && via != ViaRelay {
		return fmt.Errorf("-via must be %q or %q, got %q", ViaDirect, ViaRelay, via)
	}
	// 自己的 uuid 是对端认人的唯一凭证, 不合法就没必要跑一趟网络才被拒(同 sendFile)。
	if !conf.IsValidUUID(cfg.UUID) {
		return errors.New("websocket.client.uuid is empty or not a valid uuid, refusing to pull")
	}
	dir := to
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot use %s as the local directory: %w", dir, err)
	}
	// 转成绝对路径再往下传: recvFileOver 落盘后要用 filepath.Rel(dir, saved) 算相对名,
	// 而 saved 一定是绝对的 —— base 是相对路径时 Rel 直接报错, 结果就是每个文件都
	// 显示成空名字("-> " 后面什么都没有)。-send 那侧的目录来自配置、通常写的是绝对
	// 路径, 所以一直没撞上; -recv 的 -to 是人在命令行随手写的, "." 和 "./x" 才是常态。
	dir, err = filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", to, err)
	}

	sender, err := dialSender(cfg, "recv")
	if err != nil {
		return err
	}
	defer sender.close()

	// openPull 每次给出一条新的取件通道, 之后的清单/取件循环共用 —— 与 SendFiles 里
	// 那个 send 函数完全同构, 两条路径的差别只在这一层。
	var openPull func() (fileConn, error)
	switch via {
	case ViaDirect:
		// 一次直连, 所有文件共用 —— 每个文件占一条 stream, 不必反复打洞。打洞/握手的
		// 过程日志挂在 quiet 后面不显示(见 nat/file_send.go 里同一处改动的说明), 这
		// 两行独立于那套调试日志之外, 让一次性命令不至于在打洞期间空等无输出。
		fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch)...\n", from)
		punchStart := time.Now()
		rule := conf.ClientDirect{Email: from, ForwardPort: directFilePort}
		sess, err := sender.peer.ensureSession(rule)
		if err != nil {
			return fmt.Errorf("direct connect to %s failed, nothing was fetched: %w", from, err)
		}
		fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s)\n",
			from, sess.addr, time.Since(punchStart).Round(time.Millisecond))
		openPull = func() (fileConn, error) { return sender.peer.openPullStream(sess) }
	case ViaRelay:
		openPull = func() (fileConn, error) {
			conn, _, err := openRelayConn(sender.client, from, fileRelayOpPull)
			return conn, err
		}
	}

	// recvFileOver 内部那行 "saved ..." 在 daemon 场景是唯一的记录, 但这里每个文件
	// 紧接着就有一行带进度和速率的结果, 打两遍只是重复。真正的错误不走这里 —— 它们
	// 在 fileReply.Err 里, 会作为错误返回并中止整个取件。
	logf := func(format string, args ...interface{}) {
		if config.DebugLevel >= config.LevelDebug {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	remote := fmt.Sprintf("%s via %s", from, via)

	listConn, err := openPull()
	if err != nil {
		return fmt.Errorf("ask %s for a listing: %w", from, err)
	}
	entries, err := pullList(listConn, remotePath)
	listConn.Close()
	if err != nil {
		return fmt.Errorf("listing %s from %s: %w", remotePath, from, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s has nothing at %s", from, remotePath)
	}

	var total int64
	for _, e := range entries {
		total += e.Size
	}
	fmt.Fprintf(os.Stderr, "fetching %d file(s), %s from %s via %s into %s\n",
		len(entries), humanBytes(total), from, via, dir)

	var gotBytes int64
	for i, e := range entries {
		start := time.Now()
		prefix := fmt.Sprintf("[%d/%d] %s", i+1, len(entries), e.Name)
		p := newProgress(prefix, e.Size)

		var saved string
		var err error
		if chunks := planChunks(e.Size, parallel); chunks != nil {
			saved, err = recvParallel(openPull, dir, e, from, remote, logf, chunks, p)
		} else {
			var conn fileConn
			if conn, err = openPull(); err == nil {
				saved, err = pullFile(conn, dir, e, from, remote, logf, p.update)
				conn.Close()
			}
		}
		p.done()
		if err != nil {
			// 与 -send 一致: 中途出错就停下并报错退出, 不跳过继续取剩下的 —— 半份
			// 目录静默地"成功"了, 比明确失败坏得多。
			return fmt.Errorf("%s: %w", e.Name, err)
		}
		gotBytes += e.Size
		fmt.Fprintf(os.Stderr, "%s -> %s  (%s in %s, %s)\n", prefix, saved,
			humanBytes(e.Size), time.Since(start).Round(time.Millisecond), rate(e.Size, time.Since(start)))
	}
	fmt.Fprintf(os.Stderr, "done: %d file(s), %s\n", len(entries), humanBytes(gotBytes))
	return nil
}

// recvParallel 把一个文件按 chunks 描述的区间拆成多条独立连接并行取, 是 pullFile 的
// 分块版编排。每一块各自调 openPull 要一条新连接——它对 direct/relay 一视同仁, 不用
// 在这里再分 via。失败语义与 sendParallel 对称: 任意一块出错就让整份文件报错。
func recvParallel(openPull func() (fileConn, error), dir string, e filePullEntry, from, remote string,
	logf func(string, ...interface{}), chunks []chunkRange, p *progress) (string, error) {
	tid, err := newTransferID()
	if err != nil {
		return "", fmt.Errorf("generate transfer id: %w", err)
	}
	cp := newChunkProgress(len(chunks), p)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var saved string
	for i, c := range chunks {
		wg.Add(1)
		go func(i int, c chunkRange) {
			defer wg.Done()
			conn, err := openPull()
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			s, err := pullFileChunk(conn, dir, e, from, remote, logf, tid, i, len(chunks), c.offset, c.length,
				func(sent int64) { cp.update(i, sent) })
			conn.Close()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if s != "" {
				saved = s
			}
		}(i, c)
	}
	wg.Wait()
	if firstErr != nil {
		// 其它分块可能已经在接收端创建了 assembly；主动取消并清理，
		// 否则一次性 -recv 进程退出前不会等到后台 reaper 执行。
		abortChunkAssembly(tid)
		return "", firstErr
	}
	return saved, nil
}
