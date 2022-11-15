package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"mitm/logp"
	"net"
	"os"
	"strings"
	"time"
)

var options *Options

type MITM struct {
	options *Options
}

var certPem []byte = []byte(`-----BEGIN CERTIFICATE-----
MIICOTCCAaICCQCJyAK/oXXb8DANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJD
TjELMAkGA1UECBMCU1AxDzANBgNVBAcTBnNwcmluZzEPMA0GA1UEChMGc3ByaW5n
MQ8wDQYDVQQLEwZzcHJpbmcxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA1MjEw
NDE0MDhaFw0yNzA1MTkwNDE0MDhaMGExCzAJBgNVBAYTAkNOMQswCQYDVQQIEwJT
UDEPMA0GA1UEBxMGc3ByaW5nMQ8wDQYDVQQKEwZzcHJpbmcxDzANBgNVBAsTBnNw
cmluZzESMBAGA1UEAxMJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQCze1aGYOeqxg3frCx7NHCzBCpSjcABcI8cKrHZuAnB3axS/cbtZ5fb5R2p
NzWR/ytP/UKopLoyF7wcGiX/Aii3scvq6/JBxh/zwNzNyfRxazWqrRfQMlolraQh
iHTJn6DhnkFZ4zDl9NbkaV5fCRsuAYyz47HCCeUDcaTwaIiQPwIDAQABMA0GCSqG
SIb3DQEBBQUAA4GBAKbacuuOXrJEe1iMwZUMnh7aS48E/nV7Q8f1Ur3oKxb6TZ90
UZv99fcR9a6iJ/gB3QaRVkZ2ZLnHGbg5JcZAWsOQhIU0VXcRNbd4RuMHOs3ypanw
rgUlycMrHaeTw3CgN0+gYl1zDKDb6sYqlhwgw+tUkL2IDNab4rPNS0nbIImO
-----END CERTIFICATE-----`)

var keyPem []byte = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCze1aGYOeqxg3frCx7NHCzBCpSjcABcI8cKrHZuAnB3axS/cbt
Z5fb5R2pNzWR/ytP/UKopLoyF7wcGiX/Aii3scvq6/JBxh/zwNzNyfRxazWqrRfQ
MlolraQhiHTJn6DhnkFZ4zDl9NbkaV5fCRsuAYyz47HCCeUDcaTwaIiQPwIDAQAB
AoGACeI75JCHkW7wqqWXmX1My37qObuWnD2vk9SCEMRCvUtQxw00nDQ9N53JYV0p
9Q1BPFltB05y9nk6Ia4K850R0twuE1oLZ6ovV8f9o4MquAlrJ9aVCgFkekGidNMi
FzPXTPJ8ijKAx/um+2t4kGcyfzQmPdX13aP7tSIwishag+ECQQDkxwQLgSLXvQOu
0qRcyR9zVMAUFFwkQkxI+GEAVHasrxW6ZPXBLpMhD5dEfE5N1ajzMjBDGcQfvunL
0To9uLsRAkEAyNavroWSA87UmG3uEZPKi8MI+djHzBcqLcndyRuMMolTdaqMEMYQ
+E/YABHQDo4OetnFOgtt7gaGwE7s7312TwJAIpyFXSQ1XERJWVqe6Ta4Xl91C9Sk
uAubtPJ24nDk321BsUhy8b4VHkxYi1DvG9F2VQzDxnMQe+kLP/2wfQQEsQJAe0wh
qrjhvWi656GFaFEdJdRkrE5Dyq3l/RpTCGXbGiNok3JSbvHJ9Ue/SbulyWm4xf7v
sATYRirHi0Ro/VY+zQJBAJ/QDt8xG757r7UNITj5hvn3HIQMEijIw8mV4pRWKJD/
3i4AeXDOou+OQ+FM1p7mf9JkfLg1DJffCxcihKqeE3U=
-----END RSA PRIVATE KEY-----`)

func (mi *MITM) TLSListen(network, address string) (err error) {
	var cer tls.Certificate
	for {

		if mi.options.CertCRT != "" && mi.options.CertKey != "" {
			cer, err = tls.LoadX509KeyPair(mi.options.CertCRT, mi.options.CertKey)
		} else {
			cer, err = tls.X509KeyPair(certPem, keyPem)
		}
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
	logp.Debug("mitm", "client:%v local:%v remote: tcp://%v ", conn.RemoteAddr(), conn.LocalAddr(), mi.options.RemoteAddr)
	remotConn, err := net.Dial("tcp", mi.options.RemoteAddr)
	if err != nil {
		logp.Err("%v", err)
		return
	}
	go PipeThenClose(conn, remotConn)
	PipeThenClose(remotConn, conn)
}

func (mi *MITM) TLSInitHandler(conn net.Conn) {
	logp.Debug("mitm", "client:%v local:%v remote: tls://%v ", conn.RemoteAddr(), conn.LocalAddr(), mi.options.RemoteAddr)
	remotConn, err := tls.Dial("tcp", mi.options.RemoteAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		logp.Err("%v", err)
		return
	}
	go PipeThenClose(conn, remotConn)
	PipeThenClose(remotConn, conn)
}

func (mi *MITM) AddCert() (err error) {
	err = ioutil.WriteFile(mi.options.CertPath, certPem, 0644)
	return
}

func (mi *MITM) start() {
	var err error
	if mi.options.AddCert {
		err = mi.AddCert()
		if err != nil {
			logp.Err("%v", err)
		}
		return
	}
	switch mi.options.Mode {
	case "server":
		err = mi.Listen("tcp", mi.options.LocalAddr)
	case "client":
		err = mi.TLSListen("tcp", mi.options.LocalAddr)
	default:
		err = mi.TLSListen("tcp", mi.options.LocalAddr)
	}
	if err != nil {
		logp.Err("%v", err)
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
	flag.StringVar(&options.CertCRT, "crt", "", "cert crt")
	flag.StringVar(&options.CertKey, "key", "", "cert key")
	flag.StringVar(&options.Mode, "m", "", "mode, client or server, default is \"\"")
	flag.StringVar(&options.CertPath, "cert-path", "/etc/ssl/certs/abcd.xxx.adf.xx.f.mitm.pem", "add cert to this path")
	flag.BoolVar(&options.AddCert, "add-cert", false, "add cert")

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
