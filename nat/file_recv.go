package nat

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
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
// via 与 -send 对称、三选一(见 resolveVia), 且是硬限制而不是提示: "direct" 打洞直连、
// 打不通直接失败, "relay" 经服务端 B 中继(注意中继取件要求 B 也升级到本版本, 见
// FileRelayOpen.Op), 填一台公网 VPS 的 email 则打洞直连但打洞对象换成该 VPS 的盲转发
// 中继端点(见 SendFiles 的注释与 docs/direct-relay-design.md)。
//
// to 是本地存放目录, 与 -send 的 -to 共用同一个命令行参数、按场景解释成不同的东西:
// -send 时是"发给谁", -recv 时是"存哪儿"。留空则存到当前目录。
//
// parallel 与 SendFiles 同一个参数、同一个阈值判断(见 wantParallel): 单个文件够大时
// 按 e.Size(清单里已经有, 不用额外问一次)分块, 各开一条独立连接并行取, 每条连接
// 按自己实测的速度动态决定分片大小(见 chunkSizeForRate)。
//
// conflict 是本机已有同名文件时的处理方式(见 ParseConflict 与 file_conflict.go): 空串表示
// 终端里逐个询问、否则自动改名。
func RecvFiles(cfg conf.WsClient, recv, to, via string, parallel int, conflict string) error {
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
	res, err := newConflictResolver(conflict, conflictIn, os.Stderr)
	if err != nil {
		return err
	}
	parallel = clampParallel(parallel)
	actualVia, relayVia := resolveVia(via)
	if relayVia != "" {
		if relayVia == cfg.Email {
			return fmt.Errorf("-via %s is this machine's own email", relayVia)
		}
		if relayVia == from {
			return fmt.Errorf("-via %s must be a different subscriber from %s", relayVia, from)
		}
	}
	// 自己的 uuid 是对端认人的唯一凭证, 不合法就没必要跑一趟网络才被拒(同 sendFile)。
	// 中继连接还要靠它在 e2e QUIC 流里应答挑战(见 direct_relay_auth.go), 同一处校验够用。
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
	// 那个 send 函数完全同构, 两条路径的差别只在这一层。openPullChunk 是分块并行取用
	// 的版本, 接的是 worker 编号(0 开始, 一个 worker 绑一条连接), 好在 direct 路径下
	// 挑打开的那几条独立连接之一——不是 chunk 下标, 一个 worker 会陆续处理好几片。
	var openPull func() (fileConn, error)
	var openPullChunk func(worker int) (fileConn, error)
	// workers 是 recvParallel 该开几个抢活的 worker, 含义与 file_send.go 的同名变量
	// 一致: direct 下是实际打通的独立连接数, relay 下是 parallel 本身当并发上限。
	var workers int
	switch actualVia {
	case ViaDirect:
		// parallel>1 时这里可能打出最多 parallel 条相互独立的连接(见
		// ensureParallelSessions), 跟 -send 那边同一个理由: 各自维护自己的拥塞窗口,
		// 链路有丢包时聚合吞吐能接近线性提升。打洞/握手的过程日志挂在 quiet 后面不
		// 显示(见 nat/file_send.go 里同一处改动的说明), 这两行独立于那套调试日志
		// 之外, 让一次性命令不至于在打洞期间空等无输出。
		if relayVia != "" {
			fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch, blind-relayed through %s)...\n", from, relayVia)
		} else {
			fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch)...\n", from)
		}
		punchStart := time.Now()
		rule := conf.ClientDirect{Forward: conf.DirectForwardTarget{Email: from, Tag: directFileTag}, Via: relayVia}
		sessions, err := sender.peer.ensureParallelSessions(rule, parallel)
		if err != nil {
			return fmt.Errorf("direct connect to %s failed, nothing was fetched: %w", from, err)
		}
		if len(sessions) > 1 {
			fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s, %d independent connections)\n",
				from, sessions[0].addr, time.Since(punchStart).Round(time.Millisecond), len(sessions))
		} else {
			fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s)\n",
				from, sessions[0].addr, time.Since(punchStart).Round(time.Millisecond))
		}
		workers = len(sessions)
		openPull = func() (fileConn, error) { return sender.peer.openPullStream(sessions[0]) }
		openPullChunk = func(worker int) (fileConn, error) {
			return sender.peer.openPullStream(sessions[worker])
		}
	case ViaRelay:
		workers = parallel
		openPull = func() (fileConn, error) {
			conn, _, err := openRelayConn(sender.client, from, fileRelayOpPull)
			return conn, err
		}
		openPullChunk = func(int) (fileConn, error) { return openPull() }
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
	skipped := 0
	// warnedParallelNoResume 只提示一次, 理由同 file_send.go 的同名变量。
	warnedParallelNoResume := false
	for i, e := range entries {
		start := time.Now()
		prefix := fmt.Sprintf("[%d/%d] %s", i+1, len(entries), e.Name)

		// 同名协商放在进度条之前: 它要向用户提问, 进度条的定时重绘会把提示冲掉。
		plan := pullPlan{act: ConflictRename}
		if res.policy != ConflictRename {
			var perr error
			plan, perr = res.preparePull(dir, e, func(n int64) (string, error) {
				hc, err := openPull()
				if err != nil {
					return "", err
				}
				defer hc.Close()
				return pullHash(hc, e, n)
			})
			if perr != nil {
				return fmt.Errorf("%s: %w", e.Name, perr)
			}
			if plan.act == ConflictSkip {
				fmt.Fprintf(os.Stderr, "%s -> skipped\n", prefix)
				skipped++
				continue
			}
		}
		p := newProgress(prefix, e.Size)
		resumeAt := plan.resumeAt

		var saved string
		var err error
		if plan.resumePart != "" {
			// 续传(覆盖或重命名都会续)只取一段尾巴, 不做分块并行; 进度从已有的字节数起算。
			var conn fileConn
			if conn, err = openPull(); err == nil {
				saved, err = pullFileAct(conn, dir, e, from, remote, logf, func(n int64) { p.update(resumeAt + n) }, plan)
				conn.Close()
			}
		} else if wantParallel(e.Size, workers) {
			if !warnedParallelNoResume {
				warnedParallelNoResume = true
				fmt.Fprintln(os.Stderr, "note: -parallel transfers write several independent .chunks temp files and cannot be resumed if interrupted; an interrupted file restarts from scratch")
			}
			saved, err = recvParallel(openPullChunk, workers, dir, e, from, remote, logf, plan.act, p)
		} else {
			var conn fileConn
			if conn, err = openPull(); err == nil {
				saved, err = pullFileAct(conn, dir, e, from, remote, logf, p.update, plan)
				conn.Close()
			}
		}
		p.done()
		shown := p.wasShown()
		if err != nil {
			// 与 -send 一致: 中途出错就停下并报错退出, 不跳过继续取剩下的 —— 半份
			// 目录静默地"成功"了, 比明确失败坏得多。
			return fmt.Errorf("%s: %w", e.Name, err)
		}
		gotBytes += e.Size
		// 见 file_send.go 同一处的注释: 文件名已经在进度行上头单独打印过的话不再
		// 重复念它, 只续接结果; 没渲染过进度的话照旧带上文件名。
		if shown {
			fmt.Fprintf(os.Stderr, "  -> %s  (%s in %s, %s)\n", saved,
				humanBytes(e.Size), time.Since(start).Round(time.Millisecond), rate(e.Size, time.Since(start)))
		} else {
			fmt.Fprintf(os.Stderr, "%s -> %s  (%s in %s, %s)\n", prefix, saved,
				humanBytes(e.Size), time.Since(start).Round(time.Millisecond), rate(e.Size, time.Since(start)))
		}
	}
	fmt.Fprintf(os.Stderr, "done: %d file(s), %s%s\n", len(entries)-skipped, humanBytes(gotBytes), skippedNote(skipped))
	return nil
}

// recvParallel 是 sendParallel 的取件方向对应版本: 同一份 runChunkWorkers(见
// nat/file.go)编排认领/测速/按各自速度选分片大小, 这里只负责生成 transfer id、
// 把"开一条通道再取一片"接进去。openPull(w) 用 worker 编号 w 要一条通道——direct
// 路径下 w 挑打开的那几条独立连接之一(见 RecvFiles 的 openPullChunk), relay 路径
// 忽略 w, 每次都是独立会话。失败语义与 sendParallel 对称: 任意一块出错就让整份
// 文件报错, 其它 worker 认领下一片之前会先看到错误就地退出。
func recvParallel(openPull func(worker int) (fileConn, error), workers int, dir string, e filePullEntry, from, remote string,
	logf func(string, ...interface{}), act string, p *progress) (string, error) {
	tid, err := newTransferID()
	if err != nil {
		return "", fmt.Errorf("generate transfer id: %w", err)
	}
	// 进度按 worker(连接)算, 不是按 chunk 算, 理由同 sendParallel。
	cp := newChunkProgress(workers, p)
	saved, err := runChunkWorkers(e.Size, workers, cp, func(w int, offset, length int64, idx int, onProgress func(int64)) (string, error) {
		conn, err := openPull(w)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return pullFileChunk(conn, dir, e, from, remote, logf, tid, idx, offset, length, act, onProgress)
	})
	if err != nil {
		// 其它分块可能已经在接收端创建了 assembly；主动取消并清理，
		// 否则一次性 -recv 进程退出前不会等到后台 reaper 执行。
		abortChunkAssembly(tid)
		return "", err
	}
	return saved, nil
}
