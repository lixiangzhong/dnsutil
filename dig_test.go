package dnsutil

import (
	"testing"
)

func TestDig_SetDNS(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "ipv4", args: args{"114.114.114.114"}, wantErr: false},
		{name: "ipv4+port", args: args{"114.114.114.114:53"}, wantErr: false},
		{name: "host", args: args{"ns1.dns.com"}, wantErr: false},
		{name: "host+port", args: args{"ns1.dns.com:53"}, wantErr: false},
		{name: "ipv6", args: args{"2401::1"}, wantErr: false},
		{name: "ipv6+port", args: args{"2401::1:53"}, wantErr: false},
		{name: "full ipv6+port", args: args{"a:b:c:d:e:f:0:1:53"}, wantErr: false},
		{name: "empty", args: args{""}, wantErr: true},
		{name: ":", args: args{":"}, wantErr: true},
		{name: "localhost", args: args{"localhost"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Dig
			if err := d.SetDNS(tt.args.host); (err != nil) != tt.wantErr {
				t.Errorf("Dig.SetDNS(%v) error = %v, wantErr %v", tt.args.host, err, tt.wantErr)
			}
			// if _, err := d.A("google.com"); err != nil {
			// 	t.Errorf("Dig.A(%v) error = %v, wantErr %v", d.RemoteAddr, err, tt.wantErr)
			// }
		})
	}
}
