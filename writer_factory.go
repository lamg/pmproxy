package pmproxy

import (
	"bytes"
	"io"
	"os"
	"path"
	"strconv"
	"time"
)

// Dummy Writer Factory
type dWF struct {
	w *bytes.Buffer
}

func (d *dWF) Init() {
	d.NextWriter()
}

func (d *dWF) NextWriter() {
	d.w = bytes.NewBuffer(make([]byte, 0))
}

func (d *dWF) Current() (w io.Writer) {
	w = d.w
	return
}

func (d *dWF) Content() (r string) {
	r = d.w.String()
	return
}

func (d *dWF) Err() (e error) {
	e = nil
	return
}

// Writer Factory intended to use with the filesystem
type FWrite struct {
	path, baseName string
	e              error
	nw             io.WriteCloser
}

func (fw *FWrite) Init(path, baseName string) {
	fw.path, fw.baseName = path, baseName
	fw.newWriter()
}

func (fw *FWrite) newWriter() {
	fw.nw, fw.e = os.Create(path.Join(fw.path,
		fw.baseName+
			strconv.FormatInt(time.Now().Unix(), 10)+
			".log"))
}

func (fw *FWrite) Current() (w io.Writer) {
	w = fw.nw
	return
}

func (fw *FWrite) NextWriter() {
	fw.nw.Close()
	fw.newWriter()
	return
}

func (fw *FWrite) Err() (e error) {
	e = fw.e
	return
}
