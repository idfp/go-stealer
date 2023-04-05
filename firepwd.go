package main

import (
	"encoding/json"
	"encoding/asn1"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"database/sql"
	"os"
	"path/filepath"
	"io/ioutil"
	"golang.org/x/crypto/pbkdf2"
)
type Logins struct{
	NextId int `json:"nextId"`
	Logins []Login `json:"logins"`
	PotentiallyVulnerablePasswords []interface{} `json:"potentiallyVulnerablePasswords"`
	DismissedBreachAlertsByLoginGUID interface{} `json:"dismissedBreachAlertsByLoginGUID"`
	Version int `json:"version"`
}
type Login struct{
    Id int `json:"id"`
    Hostname string `json:"hostname"`
    HttpRealm interface{} `json:"httpRealm"`
    FormSubmitURL string `json:"formSubmitURL"`
    UsernameField string `json:"usernameField"`
    PasswordField string `json:"passwordField"`
    EncryptedUsername string `json:"encryptedUsername"`
    EncryptedPassword string `json:"encryptedPassword"`
    Guid string `json:"guid"`
    EncType int `json:"encType"`
    TimeCreated int `json:"timeCreated"`
    TimeLastUsed int `json:"timeLastUsed"`
    TimePasswordChanged int `json:"timePasswordChanged"`
    TimesUsed int `json:"timesUsed"`
}
func LoadLoginsData(profilePath string)(Logins, error){
	// Read the JSON file into memory
	var logins Logins
	jsonData, err := ioutil.ReadFile(profilePath + "\\logins.json")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return logins, err
	}

	// Unmarshal the JSON into an array of LoginData structs
	err = json.Unmarshal(jsonData, &logins)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return logins, err
	}

	return logins, nil
}
/** ASN1 structure
Sequence:
 field-0 = Sequence:
  field-0 = ObjectIdentifier
  field-1 = SequenceOf:
   Sequence:
    field-0 = ObjectIdentifier
    field-1 = Sequence:
	  field-0 = OctetString
      field-1 = Integer
      field-2 = Integer
      field-3 = SequenceOf:
	    ObjectIdentifier

   Sequence:
    field-0 = ObjectIdentifier
    field-1 = OctetString


 field-1 = OctetString
**/
type X struct{
	Field0 asn1.ObjectIdentifier
	Field1 []Y
}
type Y struct{
	Content asn1.RawContent
	Field0 asn1.ObjectIdentifier
}
type Y2 struct{
	Field0 asn1.ObjectIdentifier
	Field1 Z
}
type Y3 struct{
	Field0 asn1.ObjectIdentifier
	Field1 []byte
}
type Z struct{
	Field0 []byte
	Field1 int
	Field2 int
	Field3 []asn1.ObjectIdentifier
}
type EncryptedData struct {
	Field0 []byte
	Field1 EncryptedDataSeq
	Field2 []byte
}
type EncryptedDataSeq struct{
	Field0 asn1.ObjectIdentifier
	Field1 []byte
}
type Key struct {
	Field0 X
	Field1 []byte
}

func decryptAES(ciphertext, key, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)
    return plaintext, nil
}

func unpad(data []byte, blockSize int) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func decryptTripleDES(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plaintext, ciphertext)
	plaintext = unpad(plaintext, 8)

	return plaintext, nil
}

func DecodeLoginData(data string)([]byte, []byte, []byte){
	encrypted, _ := base64.StdEncoding.DecodeString(data)
	var x EncryptedData
	asn1.Unmarshal(encrypted, &x)
	keyId := x.Field0
	iv := x.Field1.Field1
	ciphertext := x.Field2
	return keyId, iv, ciphertext
}

func FirefoxCrackLoginData(profilePath string)([]Credential, error){
	key4Path := filepath.Join(profilePath, "key4.db")
	var credentials []Credential
	_, err := os.Stat(key4Path)
	if err != nil {
		return credentials, err
	}
	db, err := sql.Open("sqlite3", key4Path)
	if err != nil {
		return credentials, err
	}
	defer db.Close()

	var globalSalt []byte
	var item2 []byte
	var key Key
	var key2 Y2
	var key3 Y3

	row := db.QueryRow("SELECT item1, item2 FROM metadata WHERE id = 'password'")
	err = row.Scan(&globalSalt, &item2)
	if err != nil {
		return credentials, err
	}
	row = db.QueryRow("SELECT a11,a102 FROM nssPrivate;")
	var i1, i2 []byte
	row.Scan(&i1, &i2)
	asn1.Unmarshal(i1, &key)
	asn1.Unmarshal(key.Field0.Field1[0].Content, &key2)
	asn1.Unmarshal(key.Field0.Field1[1].Content, &key3)
	entrySalt := key2.Field1.Field0
	iterationCount := key2.Field1.Field1
	keyLength := key2.Field1.Field2
	k := sha1.Sum(globalSalt)
	respectKey := pbkdf2.Key(k[:], entrySalt, iterationCount, keyLength, sha256.New)
	iv := append([]byte{4, 14}, key3.Field1...)
	cipherT := key.Field1
	res, err := decryptAES(cipherT, respectKey, iv)
	if err != nil{
		return credentials, err
	}
	logins, err := LoadLoginsData("./profile")
	if err!= nil{
		return credentials, err
	}
	for _, login := range logins.Logins{
		fmt.Println(login.Hostname)
		_, y, z := DecodeLoginData(login.EncryptedUsername)
		username, err := decryptTripleDES(res[:24], y, z)
		if err != nil{
			return credentials, err
		}
		_, y, z = DecodeLoginData(login.EncryptedPassword)
		password, err := decryptTripleDES(res[:24], y, z)
		if err != nil{
			return credentials, err
		}
		credentials = append(credentials, Credential{login.Hostname, string(username), string(password)})
	}
	return credentials, nil
}