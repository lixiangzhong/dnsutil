[![Go Report Card](https://goreportcard.com/badge/github.com/lixiangzhong/dnsutil)](https://goreportcard.com/report/lixiangzhong/dnsutil)
[![](https://godoc.org/github.com/lixiangzhong/dnsutil?status.svg)](https://godoc.org/github.com/lixiangzhong/dnsutil)

# dnsutil
#### Golang DNS  dig功能库

```sh
go get github.com/lixiangzhong/dnsutil
```


```go
package main

import (
	"fmt"
	"github.com/lixiangzhong/dnsutil"
)

func main() {
    var dig dnsutil.Dig
    // dig.Retry=1 //retry : when write or read message return error . defualt 1
    dig.SetDNS("8.8.8.8") //or ns.xxx.com
    dig.SetEDNS0ClientSubnet("123.123.123.123")   //support edns0clientsubnet
    a, err := dig.A("google.com")  // dig a @8.8.8.8 +client=1.1.1.1
    fmt.Println(a, err)
}
```
