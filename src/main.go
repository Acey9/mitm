package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"logp"
	"net"
	"os"
	"strings"
	"time"
)

var options *Options

type MITM struct {
	options *Options
}

func (mi *MITM) TLSListen(network, address string) error {
	for {
		cer, err := tls.LoadX509KeyPair(mi.options.CertCRT, mi.options.CertKey)
		if err != nil {
			logp.Err("TLSListen.tls.config:%v", err)
			return err
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}

		srv, err := tls.Listen(network, address, config)
		if err != nil {
			logp.Err("TLSListen:%v", err)
			time.Sleep(6 * time.Second)
			continue
		}

		defer srv.Close()

		for {
			conn, err := srv.Accept()
			if err != nil {
				logp.Err("TLSListen.Accept:%v", err)
				break
			}
			switch mi.options.Mode {
			case "client":
				go mi.initHandler(conn)
			default:
				go mi.TLSInitHandler(conn)
			}

		}
		time.Sleep(6 * time.Second)
	}
	return nil
}

func (mi *MITM) Listen(network, address string) error {
	for {
		srv, err := net.Listen(network, address)
		if err != nil {
			logp.Err("Listen:%v", err)
			time.Sleep(6 * time.Second)
			continue
		}

		defer srv.Close()

		for {
			conn, err := srv.Accept()
			if err != nil {
				logp.Err("Listen.Accept:%v", err)
				break
			}

			switch mi.options.Mode {
			case "server":
				go mi.TLSInitHandler(conn)
			default:
				go mi.initHandler(conn)
			}

		}
		time.Sleep(6 * time.Second)
	}
	return nil
}

func (mi *MITM) initHandler(conn net.Conn) {
	logp.Debug("mitm", "[%v -> %v] accept", conn.RemoteAddr(), conn.LocalAddr())
	remotConn, err := net.Dial("tcp", mi.options.RemoteAddr)
	if err != nil {
		logp.Err("%v", err)
		return
	}
	go PipeThenClose(conn, remotConn)
	PipeThenClose(remotConn, conn)
}

func (mi *MITM) TLSInitHandler(conn net.Conn) {
	logp.Debug("mitm", "[%v -> %v] tls.accept", conn.RemoteAddr(), conn.LocalAddr())
	remotConn, err := tls.Dial("tcp", mi.options.RemoteAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		logp.Err("%v", err)
		return
	}
	go PipeThenClose(conn, remotConn)
	PipeThenClose(remotConn, conn)
}

func (mi *MITM) start() {
	switch mi.options.Mode {
	case "server":
		mi.Listen("tcp", mi.options.LocalAddr)
	case "client":
		mi.TLSListen("tcp", mi.options.LocalAddr)
	default:
		mi.TLSListen("tcp", mi.options.LocalAddr)
	}
}

func usage() {
	var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fmt.Fprintf(CommandLine.Output(), "Usage:\t%s [options] [argv]\n", os.Args[0])
	flag.PrintDefaults()
}

func optParse() {
	var logging logp.Logging
	var fileRotator logp.FileRotator
	var rotateEveryKB uint64
	var keepFiles int

	options = &Options{}

	flag.StringVar(&logging.Level, "l", "info", "logging level")
	flag.StringVar(&fileRotator.Path, "lp", "/var/logs", "log path")
	flag.StringVar(&fileRotator.Name, "n", "", "log name")
	flag.Uint64Var(&rotateEveryKB, "r", 1024, "rotate every MB")
	flag.IntVar(&keepFiles, "k", 50, "number of keep files")

	flag.StringVar(&options.LocalAddr, "L", "0.0.0.0:51360", "local addr")
	flag.StringVar(&options.RemoteAddr, "R", "", "remote addr")
	flag.StringVar(&options.CertCRT, "crt", "./localhost.crt", "cert crt")
	flag.StringVar(&options.CertKey, "key", "./localhost.key", "cert key")
	flag.StringVar(&options.Mode, "m", "", "mode, client or server, default is \"\"")

	logging.Files = &fileRotator
	if logging.Files.Path != "" {
		tofiles := true
		logging.ToFiles = &tofiles

		rotateKB := rotateEveryKB * 1024 * 1024
		logging.Files.RotateEveryBytes = &rotateKB
		logging.Files.KeepFiles = &keepFiles
	}

	flag.Usage = usage
	flag.Parse()

	if fileRotator.Name == "" {
		fileRotator.Name = strings.ReplaceAll(options.RemoteAddr, ".", "_")
		fileRotator.Name = strings.ReplaceAll(fileRotator.Name, ":", "__")
	}

	logp.Init("Beast", &logging)
}

func init() {
	optParse()
}

func main() {
	mitm := MITM{options: options}
	mitm.start()
}
