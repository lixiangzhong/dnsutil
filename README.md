[![Build Status](https://travis-ci.org/lixiangzhong/dnsutil.svg?branch=master)](https://travis-ci.org/lixiangzhong/dnsutil)
[![Code Coverage](https://img.shields.io/codecov/c/lixiangzhong/dnsutil/master.svg)](https://codecov.io/github/lixiangzhong/dnsutil?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/lixiangzhong/dnsutil)](https://goreportcard.com/report/lixiangzhong/dnsutil)
[![](https://godoc.org/github.com/lixiangzhong/dnsutil?status.svg)](https://godoc.org/github.com/lixiangzhong/dnsutil)

# dnsutil
#### Golang DNS  dig功能库

go get github.com/lixiangzhong/dnsutil
```go
import "github.com/lixiangzhong/dnsutil"

var dig dnsutil.Dig
dig.SetDNS("8.8.8.8") //or ns.xxx.com
//dig.SetEDNS0ClientSubnet("1.1.1.1") 
a,err:=dig.A("google.com")  //same -> dig a @8.8.8.8 +client=1.1.1.1
```
