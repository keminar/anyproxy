//TimeWriter implements io.Writer to roll daily and comporess log file time
//Clone from https://github.com/longbozhan/timewriter

package logging

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// io.WriteCloser
var _ io.WriteCloser = (*TimeWriter)(nil)

const (
	compressSuffix = ".gz"
	timeFormat     = "2006-01-02 15:04:05"
)

// TimeWriter 实体
type TimeWriter struct {
	Dir        string
	Prefix     string
	Compress   bool
	ReserveDay int

	curFilename string
	file        *os.File
	mu          sync.Mutex
	startMill   sync.Once
	millCh      chan bool
}

func (l *TimeWriter) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		if err = l.openExistingOrNew(len(p)); err != nil {
			fmt.Printf("write fail, msg(%s)\n", err)
			return 0, err
		}
	}

	if l.curFilename != l.filename() {
		l.rotate()
	}

	n, err = l.file.Write(p)

	return n, err
}

// Close 关闭
func (l *TimeWriter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.close()
}

// Rotate 初始
func (l *TimeWriter) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rotate()
}

func (l *TimeWriter) close() error {
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *TimeWriter) rotate() error {
	if err := l.close(); err != nil {
		return err
	}
	if err := l.openNew(); err != nil {
		return err
	}

	l.mill()
	return nil
}

func (l *TimeWriter) oldLogFiles() ([]logInfo, error) {
	files, err := ioutil.ReadDir(l.Dir)
	if err != nil {
		return nil, fmt.Errorf("can't read log file directory: %s", err)
	}
	logFiles := []logInfo{}

	prefix, ext := l.prefixAndExt()

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if f.Name() == filepath.Base(l.curFilename) {
			continue
		}
		if t, err := l.timeFromName(f.Name(), prefix, ext); err == nil {
			logFiles = append(logFiles, logInfo{t, f})
			continue
		} else {
			fmt.Printf("err1(%s)\n", err)
		}
		if t, err := l.timeFromName(f.Name(), prefix, ext+compressSuffix); err == nil {
			logFiles = append(logFiles, logInfo{t, f})
			continue
		} else {
			fmt.Printf("err2(%s)\n", err)
		}
	}

	sort.Sort(byFormatTime(logFiles))

	return logFiles, nil
}

func (l *TimeWriter) timeFromName(filename, prefix, ext string) (time.Time, error) {
	if !strings.HasPrefix(filename, prefix) {
		return time.Time{}, errors.New("mismatched prefix")
	}
	if !strings.HasSuffix(filename, ext) {
		return time.Time{}, errors.New("mismatched extension")
	}
	ts := filename[len(prefix) : len(filename)-len(ext)]
	if len(ts) != 8 {
		return time.Time{}, errors.New("mismatched date")
	}
	if year, err := strconv.ParseInt(ts[0:4], 10, 64); err != nil {
		return time.Time{}, err
	} else if month, _ := strconv.ParseInt(ts[4:6], 10, 64); err != nil {
		return time.Time{}, err
	} else if day, _ := strconv.ParseInt(ts[6:8], 10, 64); err != nil {
		return time.Time{}, err
	} else {
		timeStr := fmt.Sprintf("%04d-%02d-%02d 00:00:00", year, month, day)
		if location, err := time.LoadLocation("Local"); err != nil {
			return time.Time{}, err
		} else if t, err := time.ParseInLocation(timeFormat, timeStr, location); err != nil {
			return time.Time{}, err
		} else {
			return t, nil
		}
	}

}

func (l *TimeWriter) prefixAndExt() (prefix, ext string) {
	filename := filepath.Base(l.filename())
	ext = filepath.Ext(filename)
	prefix = filename[:len(filename)-len(ext)-8]
	return prefix, ext
}

func (l *TimeWriter) millRunOnce() error {
	if l.ReserveDay == 0 && !l.Compress {
		return nil
	}

	files, err := l.oldLogFiles()
	if err != nil {
		return err
	}

	var compress, remove []logInfo

	if l.ReserveDay > 0 {
		diff := time.Duration(int64(24*time.Hour) * int64(l.ReserveDay))
		cutoff := time.Now().Add(-1 * diff)

		var remaining []logInfo
		for _, f := range files {
			if f.timestamp.Before(cutoff) {
				remove = append(remove, f)
			} else {
				remaining = append(remaining, f)
			}
		}

		files = remaining
	}

	if l.Compress {
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), compressSuffix) {
				compress = append(compress, f)
			}
		}
	}

	for _, f := range remove {
		errRemove := os.Remove(filepath.Join(l.Dir, f.Name()))
		if err == nil && errRemove != nil {
			err = errRemove
		}
	}
	for _, f := range compress {
		fn := filepath.Join(l.Dir, f.Name())
		errCompress := compressLogFile(fn, fn+compressSuffix)
		if err == nil && errCompress != nil {
			err = errCompress
		}
	}

	return err
}

func (l *TimeWriter) millRun() {
	for range l.millCh {
		_ = l.millRunOnce()
	}
}

func (l *TimeWriter) mill() {
	l.startMill.Do(func() {
		l.millCh = make(chan bool, 1)
		go l.millRun()
	})
	select {
	case l.millCh <- true:
	default:
	}
}

func (l *TimeWriter) openNew() error {
	name := l.filename()
	err := os.MkdirAll(l.Dir, 0744)
	if err != nil {
		return fmt.Errorf("can't make directories for new logfile: %s", err)
	}

	mode := os.FileMode(0644)

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("can't open new logfile: %s", err)
	}
	l.curFilename = name
	l.file = f
	return nil
}

func (l *TimeWriter) openExistingOrNew(writeLen int) error {

	filename := l.filename()
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return l.openNew()
	} else if err != nil {
		return fmt.Errorf("error getting log file info: %s", err)
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return l.openNew()
	}
	l.curFilename = filename
	l.file = file
	return nil
}

func (l *TimeWriter) filename() string {
	year, month, day := time.Now().Date()
	date := fmt.Sprintf("%04d%02d%02d", year, month, day)
	name := fmt.Sprintf("%s.%s.log", l.Prefix, date)
	if l.Dir != "" {
		return filepath.Join(l.Dir, name)
	}
	return filepath.Join(os.TempDir(), name)
}

func compressLogFile(src, dst string) (err error) {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer f.Close()

	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat log file: %v", err)
	}

	gzf, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
	if err != nil {
		return fmt.Errorf("failed to open compressed log file: %v", err)
	}
	defer gzf.Close()

	gz := gzip.NewWriter(gzf)

	defer func() {
		if err != nil {
			os.Remove(dst)
			err = fmt.Errorf("failed to compress log file: %v", err)
		}
	}()

	if _, err := io.Copy(gz, f); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := gzf.Close(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(src); err != nil {
		return err
	}

	return nil
}

type logInfo struct {
	timestamp time.Time
	os.FileInfo
}

// byFormatTime sorts by newest time formatted in the name.
type byFormatTime []logInfo

func (b byFormatTime) Less(i, j int) bool {
	return b[i].timestamp.After(b[j].timestamp)
}

func (b byFormatTime) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b byFormatTime) Len() int {
	return len(b)
}
