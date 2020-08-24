package tcp

import (
	"bytes"
	"errors"
	"io"
)

const (
	defaultBufSize           = 4096
	minReadBufferSize        = 16
	maxConsecutiveEmptyReads = 100
)

var (
	errNegativeRead = errors.New("tcpReader: reader returned negative count from Read")
	//ErrBufferFull Buffer is full
	ErrBufferFull = errors.New("tcpReader: buffer full")
	//ErrNegativeCount negative count
	ErrNegativeCount = errors.New("tcpReader: negative count")
)

// A Reader implements convenience methods for reading requests
// or responses from a text protocol network connection.
type Reader struct {
	buf      []byte
	rd       io.Reader
	r, w     int // buf read and write positions
	err      error
	lastByte int // last byte read for UnreadByte; -1 means invalid
}

// NewReader returns a new Reader whose buffer has the default size.
func NewReader(rd io.Reader) *Reader {
	return NewReaderSize(rd, defaultBufSize)
}

// NewReaderWithBuf 带有前置buf内容的Reader实例
func NewReaderWithBuf(rd io.Reader, buf []byte) *Reader {
	r := new(Reader)
	r.reset(buf, rd)
	r.w = len(buf)
	return r
}

// NewReaderSize returns a new Reader whose buffer has at least the specified
// size. If the argument io.Reader is already a Reader with large enough
// size, it returns the underlying Reader.
func NewReaderSize(rd io.Reader, size int) *Reader {
	// Is it already a Reader?
	b, ok := rd.(*Reader)
	if ok && len(b.buf) >= size {
		return b
	}
	if size < minReadBufferSize {
		size = minReadBufferSize
	}
	r := new(Reader)
	r.reset(make([]byte, size), rd)
	return r
}

func (b *Reader) reset(buf []byte, r io.Reader) {
	*b = Reader{
		buf:      buf,
		rd:       r,
		lastByte: -1,
	}
}

func (b *Reader) readErr() error {
	err := b.err
	b.err = nil
	return err
}

// 一次性读一些数据，如果读出的数据大于要返回的数据则放入buf，否则不放buf
func (b *Reader) Read(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return 0, errors.New("read buf len is 0")
	}
	//当buf中已经没有未读内容
	if b.r == b.w {
		if b.err != nil {
			return 0, b.readErr()
		}
		if len(p) >= len(b.buf) {
			//要读取的内容大于buf长度，则直接从网络读取
			//因为没有先存于buf再copy到p的必要了
			n, b.err = b.rd.Read(p)
			if n < 0 {
				panic(errNegativeRead)
			}
			if n > 0 {
				b.lastByte = int(p[n-1])
			}
			return n, b.readErr()
		}
		// 一次性读取b.buf长度内容，再分多次读到p中
		// 这里不使用b.fill方法，因为b.fill会循环读取
		b.r = 0
		b.w = 0
		n, b.err = b.rd.Read(b.buf)
		if n < 0 {
			panic(errNegativeRead)
		}
		if n == 0 {
			return 0, b.readErr()
		}
		b.w += n
	}
	// 从buf的未读内容中读取尽量多的内容到p
	n = copy(p, b.buf[b.r:b.w])
	b.r += n
	b.lastByte = int(b.buf[b.r-1])
	return n, nil
}

//ReadLine 在buf中查换换行符并截断返回, 找不到就返回buf
func (b *Reader) ReadLine(dropBreak bool) (line []byte, isPrefix bool, err error) {
	line, err = b.ReadSlice('\n')
	if err == ErrBufferFull {
		// Handle the case where "\r\n" straddles the buffer.
		if len(line) > 0 && line[len(line)-1] == '\r' {
			// Put the '\r' back on buf and drop it from line.
			// Let the next call to ReadLine check for "\r\n".
			if b.r == 0 {
				// should be unreachable
				panic("bufio: tried to rewind past start of buffer")
			}
			//将读取位置前移1,把\r放回buf中，此时buf中只有1位数据
			b.r--
			line = line[:len(line)-1]
		}
		return line, true, nil
	}

	if len(line) == 0 {
		if err != nil {
			line = nil
		}
		return
	}
	err = nil

	if dropBreak {
		if line[len(line)-1] == '\n' {
			drop := 1
			if len(line) > 1 && line[len(line)-2] == '\r' {
				drop = 2
			}
			line = line[:len(line)-drop]
		}
	}
	return
}

// Size returns the size of the underlying buffer in bytes.
func (b *Reader) Size() int { return len(b.buf) }

// Buffered returns the number of bytes that can be read from the current buffer.
func (b *Reader) Buffered() int { return b.w - b.r }

// ReadSlice reads until the first occurrence of delim in the input,
// returning a slice pointing at the bytes in the buffer.
// The bytes stop being valid at the next read.
// If ReadSlice encounters an error before finding a delimiter,
// it returns all the data in the buffer and the error itself (often io.EOF).
// ReadSlice fails with error ErrBufferFull if the buffer fills without a delim.
// Because the data returned from ReadSlice will be overwritten
// by the next I/O operation, most clients should use
// ReadBytes or ReadString instead.
// ReadSlice returns err != nil if and only if line does not end in delim.
func (b *Reader) ReadSlice(delim byte) (line []byte, err error) {
	s := 0 // search start index
	for {
		// Search buffer.
		if i := bytes.IndexByte(b.buf[b.r+s:b.w], delim); i >= 0 {
			i += s
			line = b.buf[b.r : b.r+i+1]
			b.r += i + 1
			break
		}

		// Pending error?
		if b.err != nil {
			line = b.buf[b.r:b.w]
			b.r = b.w
			err = b.readErr()
			break
		}

		// Buffer full?
		if b.Buffered() >= len(b.buf) {
			b.r = b.w
			line = b.buf
			err = ErrBufferFull
			break
		}

		s = b.w - b.r // do not rescan area we scanned before

		// buf未满，继续填充数据
		b.fill() // buffer is not full
	}

	// Handle last byte, if any.
	if i := len(line) - 1; i >= 0 {
		b.lastByte = int(line[i])
	}

	return
}

// fill 填充buf数据.
func (b *Reader) fill() {
	// Slide existing data to beginning.
	if b.r > 0 {
		copy(b.buf, b.buf[b.r:b.w])
		b.w -= b.r
		b.r = 0
	}

	if b.w >= len(b.buf) {
		panic("bufio: tried to fill full buffer")
	}

	// Read new data: try a limited number of times.
	for i := maxConsecutiveEmptyReads; i > 0; i-- {
		n, err := b.rd.Read(b.buf[b.w:])
		if n < 0 {
			panic(errNegativeRead)
		}
		b.w += n
		if err != nil {
			b.err = err
			return
		}
		if n > 0 {
			return
		}
	}
	b.err = io.ErrNoProgress
}

// Peek 返回当前读取位置后面的N个字节，如果不够会调用fill填充buf
// 和Read不同的是Peek不会更新buf里读到的内容为已读
func (b *Reader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeCount
	}

	b.lastByte = -1

	for b.w-b.r < n && b.w-b.r < len(b.buf) && b.err == nil {
		b.fill() // b.w-b.r < len(b.buf) => buffer is not full
	}

	if n > len(b.buf) {
		return b.buf[b.r:b.w], ErrBufferFull
	}

	// 0 <= n <= len(b.buf)
	var err error
	if avail := b.w - b.r; avail < n {
		// not enough data in buffer
		n = avail
		err = b.readErr()
		if err == nil {
			err = ErrBufferFull
		}
	}
	return b.buf[b.r : b.r+n], err
}

// UnreadBuf 获取已读到buf但未从buf读走的内容
func (b *Reader) UnreadBuf(max int) (data []byte) {
	if max == 0 {
		return
	}
	if max > 0 && b.Buffered() > max {
		data = b.buf[b.r:(b.r + max)]
		b.r = b.r + max
	} else { // max = -1
		data = b.buf[b.r:b.w]
		b.r = b.w
	}
	if i := len(data) - 1; i >= 0 {
		b.lastByte = int(data[i])
	}
	return
}
