package nat

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UPnP IGD 端口映射。分三步: SSDP 组播发现网关 -> 取设备描述 XML 找控制入口 ->
// SOAP 调 AddPortMapping 与 GetExternalIPAddress。
//
// 全部手写而不引第三方库: 用到的只是这三个调用, 而 goupnp 那类库会把整套 UPnP 设备
// 模型都拖进来。这里只认自己需要的那几个字段, XML 里其余内容一概不解析。

const (
	// upnpSearchWait 等 SSDP 响应的时间。组播发现天然要等一会儿, 网关不会立刻回。
	upnpSearchWait = 2 * time.Second
	// upnpHTTPWait 取描述文档与调 SOAP 的超时。网关就在局域网内, 慢不到哪去。
	upnpHTTPWait = 3 * time.Second
	// upnpDesc 映射在路由器管理界面上显示的名字。
	upnpDesc = "anyproxy direct"
)

// IGD 的两种 WAN 连接服务, 光纤/以太网入户的通常是前者, PPPoE 拨号的是后者。两个都试。
var upnpServices = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// upnpMap 走 UPnP IGD 申请映射, 返回 "外网IP:外网端口"。
func upnpMap(gw net.IP, localPort uint16) (string, error) {
	location, err := ssdpDiscover()
	if err != nil {
		return "", fmt.Errorf("upnp discover: %w", err)
	}
	ctrlURL, svcType, err := upnpControlURL(location)
	if err != nil {
		return "", fmt.Errorf("upnp describe: %w", err)
	}
	localIP, err := localIPToward(gw)
	if err != nil {
		return "", fmt.Errorf("upnp local address: %w", err)
	}

	args := fmt.Sprintf(
		"<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort>"+
			"<NewProtocol>UDP</NewProtocol><NewInternalPort>%d</NewInternalPort>"+
			"<NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"+
			"<NewPortMappingDescription>%s</NewPortMappingDescription>"+
			"<NewLeaseDuration>%d</NewLeaseDuration>",
		localPort, localPort, localIP, upnpDesc, int(portmapLifetime.Seconds()))
	if _, err := soapCall(ctrlURL, svcType, "AddPortMapping", args); err != nil {
		return "", fmt.Errorf("upnp AddPortMapping: %w", err)
	}

	body, err := soapCall(ctrlURL, svcType, "GetExternalIPAddress", "")
	if err != nil {
		return "", fmt.Errorf("upnp GetExternalIPAddress: %w", err)
	}
	extIP := xmlValue(body, "NewExternalIPAddress")
	if net.ParseIP(extIP) == nil {
		return "", fmt.Errorf("upnp: gateway reported an unusable external address %q", extIP)
	}
	return net.JoinHostPort(extIP, fmt.Sprint(localPort)), nil
}

// ssdpDiscover 组播找 IGD, 返回设备描述文档的 URL。
func ssdpDiscover() (string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	target := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: ssdpPort}
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(search), target); err != nil {
		return "", err
	}

	deadline := time.Now().Add(upnpSearchWait)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		// 局域网里可能有别的 UPnP 设备(电视、音箱)也会应答, 只认带 LOCATION 的那条。
		if loc := headerValue(string(buf[:n]), "LOCATION"); loc != "" {
			return loc, nil
		}
	}
	return "", errors.New("no IGD answered the SSDP search")
}

// headerValue 从 SSDP 响应里取一个头部值, 大小写不敏感。
func headerValue(resp, key string) string {
	sc := bufio.NewScanner(strings.NewReader(resp))
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), key) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// upnpDevice 设备描述文档里我们关心的部分。其余字段一概不解析。
type upnpDevice struct {
	Services []struct {
		Type       string `xml:"serviceType"`
		ControlURL string `xml:"controlURL"`
	} `xml:"service"`
	Devices []upnpDevice `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDevice `xml:"device"`
}

// upnpControlURL 取设备描述, 在设备树里找 WAN 连接服务的控制入口。
func upnpControlURL(location string) (ctrlURL, svcType string, err error) {
	base, err := url.Parse(location)
	if err != nil {
		return "", "", fmt.Errorf("bad LOCATION %q: %w", location, err)
	}
	client := &http.Client{Timeout: upnpHTTPWait}
	resp, err := client.Get(location)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	// 描述文档正常也就几十 KB, 限一下免得被恶意/异常的设备撑爆内存。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", "", fmt.Errorf("parse device description: %w", err)
	}
	// WAN 服务挂在子设备里(IGD -> WANDevice -> WANConnectionDevice), 要递归找。
	path, svc := findUPnPService(root.Device)
	if path == "" {
		return "", "", errors.New("no WANIPConnection/WANPPPConnection service on this gateway")
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", "", fmt.Errorf("bad controlURL %q: %w", path, err)
	}
	return base.ResolveReference(ref).String(), svc, nil
}

func findUPnPService(d upnpDevice) (ctrlURL, svcType string) {
	for _, s := range d.Services {
		for _, want := range upnpServices {
			if s.Type == want && s.ControlURL != "" {
				return s.ControlURL, s.Type
			}
		}
	}
	for _, sub := range d.Devices {
		if u, t := findUPnPService(sub); u != "" {
			return u, t
		}
	}
	return "", ""
}

// soapCall 发一个 SOAP 请求, 返回响应体。
func soapCall(ctrlURL, svcType, action, args string) (string, error) {
	body := fmt.Sprintf(
		`<?xml version="1.0"?>`+
			`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" `+
			`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
			`<s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>`,
		action, svcType, args, action)

	req, err := http.NewRequest("POST", ctrlURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, svcType, action))

	client := &http.Client{Timeout: upnpHTTPWait}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// 失败响应体里有 UPnPError/errorCode, 带出来比只说 500 有用得多。
		if code := xmlValue(string(raw), "errorCode"); code != "" {
			return "", fmt.Errorf("%s: UPnP error %s", resp.Status, code)
		}
		return "", fmt.Errorf("%s", resp.Status)
	}
	return string(raw), nil
}

// xmlValue 从 SOAP 响应里抠一个标签的文本。
//
// 用字符串查找而不是 encoding/xml: SOAP 响应带命名空间前缀(<u:Xxx>/<Xxx> 都可能),
// 为一个字段定义整套结构体反而更啰嗦、也更容易被前缀变化打败。
func xmlValue(body, tag string) string {
	openTag, closeTag := "<"+tag+">", "</"+tag+">"
	i := strings.Index(body, openTag)
	if i < 0 {
		return ""
	}
	rest := body[i+len(openTag):]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// localIPToward 取本机去往 gw 时会用的源地址。UDP 的 Dial 不发包, 只让内核按路由表
// 选一次源地址, 这正是我们要的。
func localIPToward(gw net.IP) (string, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw, Port: pcpPort})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
