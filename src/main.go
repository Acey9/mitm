package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"logp"
	"net"
	"os"
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
			go mi.initHandler(conn)
		}
		time.Sleep(6 * time.Second)
	}
	return nil
}

func (mi *MITM) initHandler(conn net.Conn) {
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
	mi.TLSListen("tcp", mi.options.LocalAddr)
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
	flag.StringVar(&fileRotator.Name, "n", "mitm.log", "log name")
	flag.Uint64Var(&rotateEveryKB, "r", 1024, "rotate every MB")
	flag.IntVar(&keepFiles, "k", 20, "number of keep files")

	flag.StringVar(&options.LocalAddr, "L", "", "local addr")
	flag.StringVar(&options.RemoteAddr, "R", "", "remote addr")
	flag.StringVar(&options.CertCRT, "crt", "./localhost.crt", "cert crt")
	flag.StringVar(&options.CertKey, "key", "./localhost.key", "cert key")

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

	logp.Init("Beast", &logging)
}

func init() {
	optParse()
}

func main() {
	mitm := MITM{options: options}
	mitm.start()
}
