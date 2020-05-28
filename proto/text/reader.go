package text

import (
	"bytes"

	"github.com/keminar/anyproxy/proto/http"
	"github.com/keminar/anyproxy/proto/tcp"
)

// A Reader implements convenience methods for reading requests
// or responses from a text protocol network connection.
type Reader struct {
	R   *tcp.Reader
	buf []byte // a re-usable buffer for readContinuedLineSlice
}

// NewReader returns a new Reader reading from r.
//
// To avoid denial of service attacks, the provided bufio.Reader
// should be reading from an io.LimitReader or similar Reader to bound
// the size of responses.
func NewReader(r *tcp.Reader) *Reader {
	return &Reader{R: r}
}

// ReadLine reads a single line from r,
// eliding the final \n or \r\n from the returned string.
func (r *Reader) ReadLine(dropBreak bool) (string, error) {
	line, err := r.readLineSlice(dropBreak)
	return string(line), err
}

// ReadLineBytes is like ReadLine but returns a []byte instead of a string.
func (r *Reader) ReadLineBytes(dropBreak bool) ([]byte, error) {
	line, err := r.readLineSlice(dropBreak)
	if line != nil {
		buf := make([]byte, len(line))
		copy(buf, line)
		line = buf
	}
	return line, err
}

func (r *Reader) readLineSlice(dropBreak bool) ([]byte, error) {
	var line []byte
	for {
		l, more, err := r.R.ReadLine(dropBreak)
		if err != nil {
			return nil, err
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// Trim 去掉头和尾的空格和\t
// It does not assume Unicode or UTF-8.
func Trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

// DropBreak 去掉尾部换行
func DropBreak(line []byte) []byte {
	if line[len(line)-1] == '\n' {
		drop := 1
		if len(line) > 1 && line[len(line)-2] == '\r' {
			drop = 2
		}
		line = line[:len(line)-drop]
	}
	return line
}

// upcomingHeaderNewlines returns an approximation of the number of newlines
// that will be in this header. If it gets confused, it returns 0.
func (r *Reader) upcomingHeaderNewlines() (n int) {
	// Try to determine the 'hint' size.
	r.R.Peek(1) // force a buffer load if empty
	s := r.R.Buffered()
	if s == 0 {
		return
	}
	peek, _ := r.R.Peek(s)
	for len(peek) > 0 {
		i := bytes.IndexByte(peek, '\n')
		if i < 3 {
			// Not present (-1) or found within the next few bytes,
			// implying we're at the end ("\r\n\r\n" or "\n\n")
			return
		}
		n++
		peek = peek[i+1:]
	}
	return
}

// A ProtocolError describes a protocol violation such
// as an invalid response or a hung-up connection.
type ProtocolError string

func (p ProtocolError) Error() string {
	return string(p)
}

// ReadHeader reads a MIME-style header from r.
// The header is a sequence of possibly continued Key: Value lines
// ending in a blank line.
// The returned map m maps CanonicalMIMEHeaderKey(key) to a
// sequence of values in the same order encountered in the input.
//
// For example, consider this input:
//
//	My-Key: Value 1
//	Long-Key: Even
//	       Longer Value
//	My-Key: Value 2
//
// Given that input, ReadMIMEHeader returns the map:
//
//	map[string][]string{
//		"My-Key": {"Value 1", "Value 2"},
//		"Long-Key": {"Even Longer Value"},
//	}
//
func (r *Reader) ReadHeader() (http.Header, error) {
	var strs []string
	hint := r.upcomingHeaderNewlines()
	if hint > 0 {
		strs = make([]string, hint)
	}

	m := make(http.Header, hint)

	// The first line cannot start with a leading space.
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		line, err := r.readLineSlice(false)
		if err != nil {
			return m, err
		}
		return m, ProtocolError("malformed MIME header initial line: " + string(line))
	}
	var headerIsEnd bool
	lastEnd := make([]byte, 2)
	for {
		if headerIsEnd {
			return m, nil
		}
		kv, err := r.readLineSlice(false)
		if len(kv) == 0 {
			return m, err
		}
		// 发现头结束符，检查上一行是不是也是有换行符
		if len(kv) == 2 && kv[len(kv)-2] == '\r' && kv[len(kv)-1] == '\n' {
			if lastEnd[0] == '\r' && lastEnd[1] == '\n' {
				headerIsEnd = true
				continue
			}
		}
		// 记录当前行尾字符，为下一行检查提供帮助
		if len(kv) >= 2 {
			copy(lastEnd, kv[len(kv)-2:])
		}
		kv = DropBreak(kv)
		if len(kv) == 0 {
			return m, nil
		}

		// Key ends at first colon; should not have trailing spaces
		// but they appear in the wild, violating specs, so we remove
		// them if present.
		i := bytes.IndexByte(kv, ':')
		if i < 0 {
			return m, ProtocolError("malformed MIME header line: " + string(kv))
		}
		endKey := i
		//跳过:前的空格
		for endKey > 0 && kv[endKey-1] == ' ' {
			endKey--
		}
		key := http.CanonicalMIMEHeaderKey(string(kv[:endKey]))

		// As per RFC 7230 field-name is a token, tokens consist of one or more chars.
		// We could return a ProtocolError here, but better to be liberal in what we
		// accept, so if we get an empty key, skip it.
		if key == "" {
			continue
		}

		// 跳过: 后的空格
		i++ // skip colon
		for i < len(kv) && (kv[i] == ' ' || kv[i] == '\t') {
			i++
		}
		value := string(kv[i:])

		vv := m[key]
		if vv == nil && len(strs) > 0 {
			// More than likely this will be a single-element key.
			// Most headers aren't multi-valued.
			// Set the capacity on strs[0] to 1, so any future append
			// won't extend the slice into the other strings.
			vv, strs = strs[:1:1], strs[1:]
			vv[0] = value
			m[key] = vv
		} else {
			m[key] = append(vv, value)
		}

		if err != nil {
			return m, err
		}
	}
}
