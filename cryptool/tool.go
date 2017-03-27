package main

import (
	"flag"
	"fmt"
	"github.com/andviro/go-cryptoapi/csp"
	"io/ioutil"
)

func main() {
	certFile := flag.String("cert", "", "конфиг сервера")
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}
	//debug := flag.Bool("debug", false, "режим отладки")
	certBuf, _ := ioutil.ReadFile(*certFile)
	cert, _ := csp.ParseCert(certBuf)
	fmt.Println(cert.Info().IssuerStr())
	fmt.Println(cert.Info().SignatureAlgorithm())

	providers, _ := csp.EnumProviders()
	for _, provider := range providers {
		fmt.Println(provider)
	}

	///msg := csp.Msg.
}
