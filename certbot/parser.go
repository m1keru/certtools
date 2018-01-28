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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nightlyone/lockfile"
)

//VERSION  Версия дистриба
var VERSION = 1.6

// 1.5 - добавлен режим демона
// 1.3 - added locking
// var failedCrls []string

type customTime struct {
	time.Time
}

func (c *customTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	if err := d.DecodeElement(&v, &start); err != nil {
		return err
	}
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
	CryptoClass   string        `xml:"КлассСредствЭП"`
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

func createFileIfNotExists(path string) (*os.File, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0755)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func init() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: cfg,
	}
}

func findAndInstallCertByName(ucName string, root *UcRoot, fingerFile *os.File) {
	for _, uc := range root.Centers {
		if strings.Compare(ucName, strings.TrimSpace(uc.FullName)) == 0 {
			uc.installCrls()
			uc.installCerts(fingerFile)
		} else {
			//			fmt.Printf("debug: not equal: %s !=  %s\n", ucName, uc.FullName)
			//			fmt.Printf("debug: not equal: %x !=  %x\n", []byte(ucName), []byte(uc.FullName))
		}
	}
}

func installCertByUcFile(listfile string, root *UcRoot, fingerFile *os.File) {
	if file, err := os.Open(listfile); err != nil {
		panic("error: Cannor open list of UC CNs")
	} else {
		bufScanner := bufio.NewScanner(file)
		for bufScanner.Scan() {
			fmt.Println("----------------------------------------------------------------------------------------------------------------------------")
			fmt.Printf("%s\n", bufScanner.Text())
			fmt.Println("----------------------------------------------------------------------------------------------------------------------------")
			findAndInstallCertByName(bufScanner.Text(), root, fingerFile)
		}
	}
}

func (center *Center) installCrls() {
	for _, pak := range center.PAKs {
		for _, key := range pak.Keys {
			for _, crl := range key.Crls {
				err := installCrlToContainer(&crl)
				if err == nil {
					fmt.Printf("%-90sinstalled\n", crl)
					break
				} else {
					fmt.Printf("error:%s (try next revocation distributor)\n", err)
				}
			}
		}
	}

}

func (center *Center) installCerts(fingerFile *os.File) {
	fileContent, err := ioutil.ReadFile(fingerFile.Name())
	if err != nil {
		fmt.Println("Cannot read file" + err.Error())
	}
	for _, pak := range center.PAKs {
		for _, key := range pak.Keys {
			for _, cert := range key.Certs {
				if strings.Contains(string(fileContent), cert.Footprint) {
					fmt.Println("Сертификат уже есть: SHA1   " + cert.Footprint)
				} else {
					fmt.Println("Новый сертификат: SHA1   " + cert.Footprint)
					if err := installCertToContainer(&cert.CertData); err != nil {
						panic(err)
					}
					fmt.Printf("%-90sinstalled\n", string(cert.Serial))
				}
			}

		}
	}

}

func installCertToContainer(cert *[]byte) error {
	file, _ := makeTemp(cert)
	cmd := exec.Command("/opt/cprocsp/bin/amd64/certmgr", "-inst", "-store=mRoot", "--file="+file)
	if err := cmd.Run(); err != nil {
		panic(err)
	}

	cmd = exec.Command("/opt/cprocsp/bin/amd64/certmgr", "-inst", "-store=mCA", "--file="+file)
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

func dumpUcsFingerptints(root *UcRoot, fingerFile *os.File) {
	for _, uc := range root.Centers {
		for _, pak := range uc.PAKs {
			for _, key := range pak.Keys {
				for _, cert := range key.Certs {
					fingerFile.WriteString(string(cert.Footprint) + "\n")
				}
			}
		}
	}
	fingerFile.Close()
}

func makeListOfUCS(root *UcRoot) {
	ucFile, err := os.Create("./ucs_grabbed.list")
	if err != nil {
		log.Fatal("Cannot create file :", err)
	}
	defer ucFile.Close()
	for _, uc := range root.Centers {
		ucFile.WriteString(uc.FullName + "\n")
	}
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
	return newRoot.Version > oldRoot.Version
}

func killOnTimeout(lock *lockfile.Lockfile, timeout int64) {
	time.Sleep(time.Minute * time.Duration(timeout))
	lock.Unlock()
	log.Panic("Чето пощло не так")
}

func main() {
	runtime.GOMAXPROCS(2)
	var certPath = flag.String("certpath", "None", "путь до сертификата который проверяем (работаете только совместно c --testcert)")
	var testCert = flag.Bool("testcert", false, "флаг указывающий на режим проверки сертификата")
	var forceUpdate = flag.Bool("forceupdate", false, "флаг указывающий на игнорирование проверки версии xml")
	var version = flag.Bool("version", false, "версия дистрибутива")
	var daemon = flag.Bool("daemon", false, "запустить в режиме демона, в этом режиме интерактив недоступен")
	var listCa = flag.Bool("listca", false, "выводит список установленный корневых сертификатов в файл installed.list")
	var listCaPath = flag.String("listcapath", "installed.list", "путь куда записать список сертификатов")
	var uclist = flag.String("list", "", "путь до файла со списком аккредитованых УЦ")

	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}

	if *version {
		fmt.Println(VERSION)
		return
	}

	lock, err := lockfile.New(filepath.Join(os.TempDir(), "certbot.lock"))
	if err != nil {
		log.Fatalf("Cannot init lock. reason: %v", err)
	}
	err = lock.TryLock()

	go killOnTimeout(&lock, 60)

	if err != nil {
		log.Fatalf("Cannot lock %q, reason: %v", lock, err)
	}

	defer lock.Unlock()

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

	for do := true; do; do = *daemon {
		fmt.Println("daemon: ", *daemon)
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

		if *forceUpdate {
			root.Version = 9999999999999
		}

		//	fingerFile, err := os.Create("./fingers.list")
		fingerFile, err := createFileIfNotExists("./fingers.list")
		if err != nil {
			log.Fatal("Cannot create file :", err)
		}
		//defer fingerFile.Close()

		makeListOfUCS(&root)
		if newer := checkXMLVersion(&root, &oldRoot); newer {
			fmt.Println("У нас новая XML-ка, ну давайте запарсим и загрузим!")
			installCertByUcFile(*uclist, &root, fingerFile)
			makeListInstalledCerts(listCaPath)
			dumpUcsFingerptints(&oldRoot, fingerFile)
			if *daemon {
				continue
			}
			return
		}
		fmt.Println("Ну мы тут посовещались и решили что XML-ка не обновилась, делать ниче не будем")
	}
}
