package nat

import (
	"fmt"
	"net"
	"sort"
	"time"
)

// 直连候选地址与择优。
//
// 原先只有一个候选(反射器观测到的 IPv6 端点), 通不了就整条失败。现在改成**多条路
// 同时打**: IPv4、IPv6、端口映射(UPnP/PCP), 全部并行探测, 哪条先回包就先被观测到。
//
// 不收本机接口地址那一类候选: 那只在"两台机器同网段"时才有用, 而面向的场景是跨网
// (中间隔着 CGNAT 或真正的公网), 同网段直连不是要解决的问题(见 direct_reflect.go
// 的 gatherCandidates)。candSrcLocal 仍留着给测试当通用标签用, 也留一条以后要做
// 同网段优化时的接口。
//
// 多条都通时才谈优先级, 按实测 RTT 选, 并按地址类型给一个偏置(相当于给它减去一点
// RTT, 让它更容易胜出):
//
//	回环          -50ms   最优先, 同机
//	链路本地      -30ms   次之, 同二层
//	私有 / CGNAT  -20ms   同网段直连优于绕公网
//	公网          0       基准
//
// 这套偏置分档是通用的评分规则, 不是专为哪一类候选来源定的: 即使目前的候选来源都
// 是跨网场景产出的公网/CGNAT 地址, 分档逻辑本身不需要跟着改。
//
// IPv4 与 IPv6 的**公网**地址是平等竞争的, 偏置都是 0, 纯比实测 RTT。这里没有"优先
// IPv6"这种先验 —— 之前那套 IPv6-only 是因为当时只有那条路通, 不是因为它更好。

// 候选来源, 仅用于日志与排查, 不参与择优(择优只看地址类型与 RTT)。
const (
	candSrcReflectV4 = "v4"      //反射器观测到的 IPv4 端点
	candSrcReflectV6 = "v6"      //反射器观测到的 IPv6 端点
	candSrcPortmap   = "portmap" //UPnP / PCP / NAT-PMP 映射来的端点
	candSrcLocal     = "local"   //本机接口上的地址; 目前没有代码会产出这类候选(见上), 常量留给测试用
)

// 地址类型偏置。数值是**减去**的 RTT, 所以越负越优先。
const (
	biasLoopback  = -50 * time.Millisecond
	biasLinkLocal = -30 * time.Millisecond
	biasPrivate   = -20 * time.Millisecond
	biasPublic    = 0
)

// directCandidate 一个可尝试的对端端点。
type directCandidate struct {
	Addr   string `json:"addr"` //host:port
	Source string `json:"src"`  //来源(见 candSrc*), 只用于日志
}

func (c directCandidate) String() string { return fmt.Sprintf("%s(%s)", c.Addr, c.Source) }

// candidateBias 按地址类型给偏置。无法解析的地址按公网处理(不给优惠, 也不排除)。
func candidateBias(host string) time.Duration {
	ip := net.ParseIP(host)
	if ip == nil {
		return biasPublic
	}
	switch {
	case ip.IsLoopback():
		return biasLoopback
	case ip.IsLinkLocalUnicast():
		return biasLinkLocal
	case ip.IsPrivate() || isCGNAT(ip):
		// CGNAT(100.64/10) 归到私有一档: 运营商大内网里的对端, 走这个地址就是在
		// 同一张运营商网内直连, 比绕到公网再回来更近。
		return biasPrivate
	default:
		return biasPublic
	}
}

// isCGNAT 判断是否落在 100.64.0.0/10 (RFC 6598 运营商级 NAT 专用段)。
// net.IP.IsPrivate 只认 RFC 1918 与 fc00::/7, 不含这一段。
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// candidateResult 一个候选的探测结果。
type candidateResult struct {
	Cand directCandidate
	RTT  time.Duration
	Err  error //非空表示这条没通, 不参与择优
}

// score 择优用的分数: 实测 RTT 加上地址类型偏置, 越小越好。
func (r candidateResult) score() time.Duration {
	host, _, err := net.SplitHostPort(r.Cand.Addr)
	if err != nil {
		host = r.Cand.Addr
	}
	return r.RTT + candidateBias(host)
}

// selectCandidate 从探测结果里挑一条。只在通了的里面挑; 一条都没通就报错, 并把各条
// 的失败原因带出来 —— 直连失败时最需要知道的就是"每条路分别卡在哪", 而不是一句
// "连不上"。
func selectCandidate(results []candidateResult) (directCandidate, error) {
	var ok []candidateResult
	for _, r := range results {
		if r.Err == nil {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return directCandidate{}, fmt.Errorf("no candidate answered: %s", describeFailures(results))
	}
	// 稳定排序 + 地址做次级键: 分数相同时结果要可复现, 否则同样的两条路每次选的不
	// 一样, 排查时看到的日志对不上。
	sort.SliceStable(ok, func(i, j int) bool {
		si, sj := ok[i].score(), ok[j].score()
		if si != sj {
			return si < sj
		}
		return ok[i].Cand.Addr < ok[j].Cand.Addr
	})
	return ok[0].Cand, nil
}

// describeFailures 把每条候选的失败原因拼成一行。
func describeFailures(results []candidateResult) string {
	if len(results) == 0 {
		return "no candidate was even attempted"
	}
	s := ""
	for i, r := range results {
		if i > 0 {
			s += "; "
		}
		reason := "no reply"
		if r.Err != nil {
			reason = r.Err.Error()
		}
		s += fmt.Sprintf("%s: %s", r.Cand, reason)
	}
	return s
}

// describeResults 把择优过程打成一行日志: 每条候选的 RTT、偏置、最终分数。直连选了
// 哪条、为什么选它, 不打出来就只能靠猜。
func describeResults(results []candidateResult, winner directCandidate) string {
	s := ""
	for i, r := range results {
		if i > 0 {
			s += ", "
		}
		if r.Err != nil {
			s += fmt.Sprintf("%s failed", r.Cand)
			continue
		}
		host, _, err := net.SplitHostPort(r.Cand.Addr)
		if err != nil {
			host = r.Cand.Addr
		}
		mark := ""
		if r.Cand.Addr == winner.Addr {
			mark = " <-"
		}
		s += fmt.Sprintf("%s rtt=%s bias=%s score=%s%s",
			r.Cand, r.RTT.Round(time.Millisecond), candidateBias(host), r.score().Round(time.Millisecond), mark)
	}
	return s
}

// dedupCandidates 去掉重复地址, 保留先出现的那条(来源信息以先到者为准)。
// 同一个端点常会从多个来源冒出来(例如本机接口地址恰好就是公网地址, 与反射器观测到的
// 是同一个), 重复探测纯属浪费, 还会让日志难读。
func dedupCandidates(cands []directCandidate) []directCandidate {
	seen := map[string]bool{}
	out := make([]directCandidate, 0, len(cands))
	for _, c := range cands {
		if c.Addr == "" || seen[c.Addr] {
			continue
		}
		seen[c.Addr] = true
		out = append(out, c)
	}
	return out
}
