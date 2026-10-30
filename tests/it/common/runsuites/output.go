/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package runsuites

import (
	"bytes"
	"io"
	"sync"
)

// LineWriter writes whole lines, each beginning with a prefix, to a shared output. Writers that
// share one mutex never split each other's lines, so the output of blocks that run at the same
// time can stream to one log.
type LineWriter struct {
	mu      *sync.Mutex
	out     io.Writer
	prefix  []byte
	partial []byte
}

// NewLineWriter returns a writer that prefixes every line it writes to out. mu is held while a
// line is written and must be shared by every writer of out.
func NewLineWriter(out io.Writer, mu *sync.Mutex, prefix string) *LineWriter {
	return &LineWriter{mu: mu, out: out, prefix: []byte(prefix)}
}

// Write writes the complete lines of p, and keeps the rest until the line ends or Flush is called.
// It is for one stream; callers that write from several goroutines must serialise their writes.
func (w *LineWriter) Write(p []byte) (int, error) {
	w.partial = append(w.partial, p...)
	for {
		end := bytes.IndexByte(w.partial, '\n')
		if end < 0 {
			return len(p), nil
		}
		if err := w.line(w.partial[:end+1]); err != nil {
			return len(p), err
		}
		w.partial = w.partial[end+1:]
	}
}

// Flush writes the unfinished line, if there is one, ended with a newline.
func (w *LineWriter) Flush() error {
	if len(w.partial) == 0 {
		return nil
	}
	line := append(w.partial, '\n')
	w.partial = nil
	return w.line(line)
}

func (w *LineWriter) line(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.out.Write(w.prefix); err != nil {
		return err
	}
	_, err := w.out.Write(line)
	return err
}
