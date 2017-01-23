package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var failedCrls []string

type customTime struct {
	time.Time
}

func (c *customTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	d.DecodeElement(&v, &start)
	parse, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return err

	}
	*c = customTime{parse}
	return nil

}

//UcRoot  Корень списка УЦ
type UcRoot struct {
	XMLName xml.Name `xml:"АккредитованныеУдостоверяющиеЦентры"`
	Centers []Center `xml:"УдостоверяющийЦентр"`
	Version int64    `xml:"Версия"`
}

//Center  Структура Содержащая информацию по УЦ
type Center struct {
	XMLName   xml.Name      `xml:"УдостоверяющийЦентр"`
	FullName  string        `xml:"Название"`
	Email     string        `xml:"ЭлектроннаяПочта"`
	ShortName string        `xml:"КраткоеНазвание"`
	InfoURL   string        `xml:"АдресСИнформациейПоУЦ"`
	Address   CenterAddress `xml:"Адрес"`
	PAKs      []PAK         `xml:"ПрограммноАппаратныеКомплексы>ПрограммноАппаратныйКомплекс"`
}

//CenterAddress Структура содержащая адреса УЦ и ПАК
type CenterAddress struct {
	XMLName xml.Name `xml:"Адрес"`
	Country string   `xml:"Страна"`
	ZIP     int64    `xml:"Индекс"`
	Street  string   `xml:"УлицаДом"`
	City    string   `xml:"Город"`
}

//PAK структура содержащая информацию о ПАК
type PAK struct {
	XMLName       xml.Name      `xml:"ПрограммноАппаратныйКомплекс"`
	Alias         string        `xml:"Псевдоним"`
	CryptoClass   string        `xml:""КлассСредствЭП"`
	PakAddress    CenterAddress `xml:"Адрес"`
	CryptoVersion string        `xml:"СредстваУЦ"`
	Keys          []Key         `xml:"КлючиУполномоченныхЛиц>Ключ"`
}

//Key структура содержащая информацию о Ключе СКЗИ
type Key struct {
	XMLName xml.Name `xml:"Ключ"`
	KeyID   []byte   `xml:"ИдентификаторКлюча"`
	Crls    []string `xml:"АдресаСписковОтзыва>Адрес"`
	Certs   []Cert   `xml:"Сертификаты>ДанныеСертификата"`
}

//Cert структура содержащая информацию о Сертифике выданном ПАК
type Cert struct {
	XMLName   xml.Name   `xml:"ДанныеСертификата"`
	Footprint string     `xml:"Отпечаток"`
	Issuer    string     `xml:"КемВыдан"`
	Subject   string     `xml:"КомуВыдан"`
	Serial    []byte     `xml:"СерийныйНомер"`
	ValidFrom customTime `xml:"ПериодДействияС"`
	ValidThru customTime `xml:"ПериодДействияДо"`
	CertData  []byte     `xml:"Данные"`
}

func init() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: cfg,
	}
}

func findAndInstallCertByName(ucName string, root *UcRoot) {
	for _, uc := range root.Centers {
		if strings.Compare(ucName, uc.FullName) == 0 {
			uc.installCrls()
			uc.installCerts()
		}
	}
}

func findAndInstallUcByAlias(alias string, root *UcRoot) {
	for _, uc := range root.Centers {
		if strings.Compare(alias, uc.ShortName) == 0 {
			go uc.installCrls()
			go uc.installCerts()
		}
	}

}

func installCertByUcFile(listfile string, root *UcRoot) {
	if file, err := os.Open(listfile); err != nil {
		panic("error: Cannor open list of UC CNs")
	} else {
		bufScanner := bufio.NewScanner(file)
		for bufScanner.Scan() {
			fmt.Println("----------------------------------------------------------------------------------------------------------------------------")
			fmt.Printf("%s\n", bufScanner.Text())
			fmt.Println("----------------------------------------------------------------------------------------------------------------------------")
			findAndInstallCertByName(bufScanner.Text(), root)
		}
	}
}

func (center *Center) installCrls() {
	for _, pak := range center.PAKs {
		for _, key := range pak.Keys {
			for _, crl := range key.Crls {
				err := installCrlToContainer(&crl)
				if err == nil {
					fmt.Printf("%-90sisntalled\n", crl)
					break
				} else {
					fmt.Printf("error:%s (try next revocation distributor)\n", err)
				}
			}

		}
	}

}

func (center *Center) installCerts() {
	for _, pak := range center.PAKs {
		for _, key := range pak.Keys {
			for _, cert := range key.Certs {
				if err := installCertToContainer(&cert.CertData); err != nil {
					panic(err)
				}
				fmt.Printf("%-90sinstalled\n", string(cert.Serial))
			}

		}
	}

}

func installCertToContainer(cert *[]byte) error {
	file, _ := makeTemp(cert)
	cmd := exec.Command("/opt/cprocsp/bin/amd64/certmgr", "-inst", "-store=root", "--file="+file)
	if err := cmd.Run(); err != nil {
		panic(err)
	}
	defer os.Remove(file)
	return nil
}

func installCrlToContainer(cert *string) error {
	content, err := getCrlByURL(cert)
	if err != nil {
		return err
	}
	file, _ := makeTemp(&content)
	cmd := exec.Command("/opt/cprocsp/bin/amd64/certmgr", "-inst", "-store=mCA", "-crl", "--file="+file)
	if err := cmd.Run(); err != nil {
		if err.Error() == "exit status 45" {
			fmt.Printf("error:%3scrl not valid:%s\n", " ", *cert)
			return errors.New("CRLNVAL")
		}
	}
	defer os.Remove(file)
	return nil
}

func isCertAlreadyInstalled(root *UcRoot) {
	// MAKE LIST OF SHA1
}

func testUserCert(certPath string) {
	cmd := exec.Command("/opt/cprocsp/bin/amd64/cryptcp", "-verify", "-errchain", "-f", certPath, certPath)
	//var stderr bytes.Buffer
	var stdout bytes.Buffer
	//cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	cmd.Run()
	/*if err != nil {
		log.Fatal(stderr.String())
		return
	}*/
	fmt.Println(stdout.String())
}

func makeListInstalledCerts(listCaPath *string) {
	fmt.Println("--------------- создаем список установленных сертификатов -----------------------")
	cmd := exec.Command("/bin/bash", "-c", "/opt/cprocsp/bin/amd64/certmgr -list -store root |grep 'Serial' |cut -d':' -f2| sed -e 's/^[[:space:]]//' > "+*listCaPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Run()
	//fmt.Println(stdout.String())
}

func getCrlByURL(crl *string) ([]byte, error) {
	supportedProtos := map[string]bool{"http": true, "ftp": false}
	if supportedProtos[strings.Split(*crl, ":")[0]] == false {
		return nil, errors.New("unsupported proto")
	}

	timeout := time.Duration(2 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	response, err := client.Get(*crl)
	if err != nil {
		return nil, err
	}
	fileContent, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func getRosreestrXML(url string) {
	response, err := http.Get(url)
	if err != nil {
		panic("can't download rosreestr XML" + err.Error())
	}
	fileContent, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic("cannot download rosreestr XML")
	}
	if err := ioutil.WriteFile("./uc.xml", fileContent, 0600); err != nil {
		panic("can not save rosreestr XML to uc.xml")
	}

}

func makeTemp(bytes *[]byte) (string, error) {
	file, err := ioutil.TempFile("/tmp/", "__certParserTmp__")
	defer file.Close()
	if err != nil {
		panic("Cannot create TempFile")
	}
	if err := ioutil.WriteFile(file.Name(), *bytes, 0600); err != nil {
		panic(err)
	}
	return file.Name(), nil
}

func checkXMLVersion(newRoot *UcRoot, oldRoot *UcRoot) bool {
	return (newRoot.Version > oldRoot.Version)
}

func main() {
	var certPath = flag.String("certpath", "None", "путь до сертификата который проверяем (работаете только совместно c --testcert)")
	var testCert = flag.Bool("testcert", false, "флаг указывающий на режим проверки сертификата")
	var listCa = flag.Bool("listca", false, "выводит список установленный корневых сертификатов в файл installed.list")
	var listCaPath = flag.String("listcapath", "installed.list", "путь куда записать список сертификатов")
	var uclist = flag.String("list", "", "путь до файла со списком аккредитованых УЦ")
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}
	if *testCert {
		fmt.Println("------------ режим тестирования ------------------")
		if *certPath == "None" {
			flag.Usage()
			return
		}
		testUserCert(*certPath)
		return
	}

	if *listCa {
		makeListInstalledCerts(listCaPath)
		return
	}

	fmt.Printf("----------------------Запуск %s -----------------------\n", time.Now().String())
	logwriter, e := syslog.New(syslog.LOG_NOTICE, "certparser")
	if e == nil {
		log.SetOutput(logwriter)
	}

	oldRoot := UcRoot{}
	oldXMLFile, err := ioutil.ReadFile("./uc.xml")

	if err == nil {
		err = xml.Unmarshal(oldXMLFile, &oldRoot)
		if err != nil {
			panic(err.Error())
		}
	} else {
		oldRoot.Version = 0
		fmt.Println("Похоже что это свежая установка или вы грохнули старую XML-ку")
	}

	getRosreestrXML("https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0")

	root := UcRoot{}
	xmlFile, err := ioutil.ReadFile("./uc.xml")
	if err != nil {
		panic(err.Error())
	}
	err = xml.Unmarshal(xmlFile, &root)
	if err != nil {
		panic(err.Error())
	}

	if newer := checkXMLVersion(&root, &oldRoot); newer {
		fmt.Println("У нас новая XML-ка, ну давайте запарсим и загрузим!")
		installCertByUcFile(*uclist, &root)
		makeListInstalledCerts(listCaPath)
		return
	}
	fmt.Println("Ну мы тут посовещались и решили что XML-ка не обновилась, делать ниче не будем")
}
