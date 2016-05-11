package dnsutil

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

const (
	dnsTimeout time.Duration = 3 * time.Second
)

type Dig struct {
	LocalAddr    string
	RemoteAddr   string
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

func (d *Dig) dialTimeout() time.Duration {
	if d.DialTimeout != 0 {
		return d.DialTimeout
	}
	return dnsTimeout
}
func (d *Dig) readTimeout() time.Duration {
	if d.ReadTimeout != 0 {
		return d.ReadTimeout
	}
	return dnsTimeout
}
func (d *Dig) writeTimeout() time.Duration {
	if d.WriteTimeout != 0 {
		return d.WriteTimeout
	}
	return dnsTimeout
}
func (d *Dig) remoteAddr() string {
	if strings.HasSuffix(d.RemoteAddr, ":53") {
		return d.RemoteAddr
	}
	return fmt.Sprintf("%s:53", d.RemoteAddr)
}
func (d *Dig) conn() (net.Conn, error) {
	if d.LocalAddr == "" {
		return net.DialTimeout("udp", d.remoteAddr(), d.dialTimeout())
	}
	dialer := new(net.Dialer)
	dialer.Timeout = d.dialTimeout()
	var err error
	dialer.LocalAddr, err = net.ResolveUDPAddr("udp", d.LocalAddr+":0")
	if err != nil {
		return nil, err
	}
	return dialer.Dial("udp", d.remoteAddr())
}

func newMsg(Type uint16, domain string) *dns.Msg {
	if !strings.HasSuffix(domain, ".") {
		domain = fmt.Sprintf("%s.", domain)
	}
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   domain,
		Qtype:  Type,
		Qclass: dns.ClassINET,
	}
	return msg
}
func (d *Dig) exchange(m *dns.Msg) (*dns.Msg, error) {
	var err error
	c := new(dns.Conn)
	c.Conn, err = d.conn()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(d.writeTimeout()))
	c.SetReadDeadline(time.Now().Add(d.readTimeout()))
	err = c.WriteMsg(m)
	if err != nil {
		return nil, err
	}
	res, err := c.ReadMsg()
	if err != nil {
		return nil, err
	}
	return res, nil
}
func (d *Dig) SetDNS(IP string) {
	if strings.HasSuffix(IP, ":53") {
		d.RemoteAddr = IP
	}
	d.RemoteAddr = fmt.Sprintf("%s:53", IP)
}
func (d *Dig) A(domain string) ([]*dns.A, error) {
	m := newMsg(dns.TypeA, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var As []*dns.A
	for _, v := range res.Answer {
		if a, ok := v.(*dns.A); ok {
			As = append(As, a)
		}
	}
	return As, nil
}
func (d *Dig) NS(domain string) ([]*dns.NS, error) {
	m := newMsg(dns.TypeNS, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var Ns []*dns.NS
	for _, v := range res.Answer {
		if ns, ok := v.(*dns.NS); ok {
			Ns = append(Ns, ns)
		}
	}
	return Ns, nil
}
func (d *Dig) CNAME(domain string) ([]*dns.CNAME, error) {
	m := newMsg(dns.TypeCNAME, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var C []*dns.CNAME
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CNAME); ok {
			C = append(C, c)
		}
	}
	return C, nil
}
func (d *Dig) TXT(domain string) ([]*dns.TXT, error) {
	m := newMsg(dns.TypeTXT, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var T []*dns.TXT
	for _, v := range res.Answer {
		if t, ok := v.(*dns.TXT); ok {
			T = append(T, t)
		}
	}
	return T, nil
}
func (d *Dig) MX(domain string) ([]*dns.MX, error) {
	msg := newMsg(dns.TypeMX, domain)
	res, err := d.exchange(msg)
	if err != nil {
		return nil, err
	}
	var M []*dns.MX
	for _, v := range res.Answer {
		if m, ok := v.(*dns.MX); ok {
			M = append(M, m)
		}
	}
	return M, nil
}
func (d *Dig) ANY(domain string) ([]dns.RR, error) {
	m := newMsg(dns.TypeANY, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	return res.Answer, nil
}
