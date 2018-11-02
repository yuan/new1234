package main

import (
	"C"
	"fmt"
	"net/http"
	"net/url"

	"strings"

	"golang.org/x/net/html"

	"io/ioutil"
	"os"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"log"

	"golang.org/x/sys/windows/registry"
)

var infoLogger = createLogger("info.log", "[info]")
var errorLogger = createLogger("error.log", "[error]")

const (
	openvpn_gui_registry               = `Software\OpenVPN-GUI`
	openvpn_gui_registry_config_dir    = "config_dir"
	openvpn_gui_registry_corp_account  = "corp_account"
	openvpn_gui_registry_corp_password = "corp_password"

	aes_key = "openvpn gui netease 1234"
)

func main() {
}

//export SaveNeteaseCorpInfo
func SaveNeteaseCorpInfo(account string, password string) {
	_account := specialFormat(account)
	_password := specialFormat(password)
	setRegistry(openvpn_gui_registry_corp_account, _account)
	setRegistry(openvpn_gui_registry_corp_password, encrypt([]byte(aes_key), _password))
	doAutoConnect()
}

func specialFormat(account string) string {
	len := len(account)
	if len == 0 {
		return ""
	}
	var buf bytes.Buffer
	for i := 0; i < len; i++ {
		if i%2 != 0 {
			continue
		}
		buf.WriteByte(account[i])
	}
	return buf.String()
}

//export GetNeteaseCorpAccount
func GetNeteaseCorpAccount() *C.char {
	return C.CString(getRegistry(openvpn_gui_registry_corp_account))
}

//export GetNeteaseCorpPassword
func GetNeteaseCorpPassword() *C.char {
	password := decrypt([]byte(aes_key), getRegistry(openvpn_gui_registry_corp_password))
	return C.CString(password)
}

//export AutoConnectOpenVPN
func AutoConnectOpenVPN() {
	doAutoConnect()
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		for _ = range ticker.C {
			doAutoConnect()
		}
	}()
}

func doAutoConnect() {
	s := getRegistry(openvpn_gui_registry_config_dir)
	correctConfigDir := s != ""
	if !correctConfigDir {
		Error("Fail to get config_dir from registry")
	}
	// Info("Begin to fetch password...")
	fetchSuccess := correctConfigDir && (fetchPassword(s, false) || fetchPassword(s, true))
	if !fetchSuccess {
		Error("Fail to fetch password")
	}
	files, _ := ioutil.ReadDir(s)
	for _, f := range files {
		filePath := s + "\\" + f.Name()
		if f.IsDir() || !strings.HasSuffix(filePath, ".ovpn") {
			continue
		}
		file, err := os.Open(filePath)
		if err != nil {
			Info("Fail to open system_hosts: %s", err)
			continue
		}
		defer file.Close()
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Println(err)
		}
		lines := strings.Split(string(content), "\n")
		autoConnect := false

		for i, l := range lines {
			line := strings.TrimSpace(l)
			if strings.Contains(line, "vpn.cloud.netease.com") {
				autoConnect = true
			}
			if strings.Contains(line, "auth-user-pass") {
				if fetchSuccess {
					lines[i] = "auth-user-pass pass.txt"
				} else {
					lines[i] = "auth-user-pass"
				}
			}
		}
		if autoConnect {
			if err := ioutil.WriteFile(filePath, []byte(strings.Join(lines, "\n")), os.ModeExclusive); err != nil {
				Error("Error writing to ovpn file: %v", filePath)
			}
		}
	}
}

func fetchPassword(configDir string, mesg bool) bool {
	account := char2string(GetNeteaseCorpAccount())
	password := char2string(GetNeteaseCorpPassword())
	if account == "" || password == "" {
		return false
	}
	req, _ := http.NewRequest("GET", "https://login.netease.com/openid/?&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.sreg.required=email&openid.realm=http%3A%2F%2Fcloud-i.netease.com%2F&openid.assoc_handle=&openid.return_to=http%3A%2F%2Fcloud-i.netease.com%2Fvpn", nil)
	resp, _ := http.DefaultTransport.RoundTrip(req)

	data := url.Values{}
	data.Add("trust_root", "http://cloud-i.netease.com/")
	if !mesg {
		data.Add("authm", "corp")
		data.Add("corpid", fmt.Sprintf("%s@corp.netease.com", account))
		data.Add("corppw", password)
	} else {
		data.Add("authm", "mesg")
		data.Add("mesgid", fmt.Sprintf("%s@mesg.corp.netease.com", account))
		data.Add("mesgpw", password)
	}
	res, _ := http.PostForm(resp.Header.Get("Location"), data)
	doc, err := html.Parse(res.Body)
	if err != nil {
		fmt.Println(err)
		return false
	}
	result := []string{}
	slice := []*html.Node{doc}
	for index := 0; index < len(slice); index++ {
		node := slice[index]
		if node.Type == html.ElementNode && node.Data == "p" {
			for _, a := range node.Attr {
				if a.Key == "id" && strings.HasPrefix(a.Val, "vpn") {
					result = append(result, node.FirstChild.Data)
					break
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			slice = append(slice, c)
		}
	}
	if len(result) == 0 {
		return false
	}
	passPath := configDir + "\\pass.txt"
	if err := ioutil.WriteFile(passPath, []byte(strings.Join(result, "\n")), os.ModeExclusive); err == nil {
		return true
	} else {
		Error("Error writing to pass file: %v", passPath)
		return false
	}
}

func setRegistry(key, value string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, openvpn_gui_registry, registry.WRITE)
	if err != nil {
		Error("Fail to Open registry %s, %v", openvpn_gui_registry, err)
		return false
	}
	defer k.Close()
	if err := k.SetStringValue(key, value); err != nil {
		Error("Fail to set registry %s:%s, %v", key, value, err)
		return false
	}
	return true
}

func getRegistry(key string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, openvpn_gui_registry, registry.READ)
	if err != nil {
		Error("Fail to Open registry %s, %v", openvpn_gui_registry, err)
		return ""
	}
	defer k.Close()
	value, _, err := k.GetStringValue(key)
	if err != nil {
		Error("Fail to get registry by key %s, %v", key, err)
		return ""
	}
	return value
}

func encrypt(key []byte, text string) string {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key)
	if err != nil {
		Error("[encrypt] Fail to NewCipher %s, %v", text, err)
		return ""
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		Error("[encrypt] Fail to ReadFull %s, %v", text, err)
		return ""
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		Error("[decrypt] Fail to NewCipher %s, %v", cryptoText, err)
		return ""
	}
	if len(ciphertext) < aes.BlockSize {
		Error("[decrypt] ciphertext too short %s, %v", ciphertext, err)
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return fmt.Sprintf("%s", ciphertext)
}

func char2string(char *C.char) string {
	return fmt.Sprintf("%s", C.GoString(char))
}

func createLogger(file string, prefix string) *log.Logger {
	var f *os.File
	var err error
	if f, err = openFile(file); err != nil {
		if f, err = os.Create(file); err != nil {
			defer f.Close()
			panic(err)
		}
	}
	return log.New(f, prefix, log.LstdFlags|log.Lmicroseconds)
}

func openFile(file string) (*os.File, error) {
	if f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil && os.IsNotExist(err) {
		return nil, err
	} else {
		return f, nil
	}
}

func Info(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	log.Println(message)
	infoLogger.Println(message)
}

func Error(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	log.Println(message)
	errorLogger.Println(message)
}

func Fatal(format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	errorLogger.Println(message)
	log.Fatalln(message)
}
