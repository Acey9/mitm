package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	//"io"
	"logp"
	"net"
	"time"
)

const readTimeout = 60

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(time.Duration(readTimeout) * time.Second))
	}
}

func Compress(source []byte) bytes.Buffer {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(source)
	w.Close()
	return buf
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn) {
	defer src.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			payload := Compress(buf[:n])
			logp.Info("[%v -> %v] %v", src.RemoteAddr(), dst.RemoteAddr(), base64.StdEncoding.EncodeToString(payload.Bytes()))
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				logp.Err("write:%v", err)
				break
			}
		}
		if err != nil {
			logp.Err("read:%v", err)
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}
