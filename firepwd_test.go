package main

import (
	"testing"
	"log"
	"fmt"
)

func TestJsonLoads(t *testing.T) {
	logins, err := LoadLoginsData("./profile")
	if err!= nil{
		log.Fatal(err)
	}
	if logins.Logins == nil{
		t.Errorf("Logins object isn't supposed to be empty.")
	}
	for _, login := range logins.Logins{
		fmt.Println(login.hostname)
	}
}