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
