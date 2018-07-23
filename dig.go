package dnsutil

import (
	"errors"
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
	EDNSSubnet   net.IP
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	Protocol     string
}

func (d *Dig) protocol() string {
	if d.Protocol != "" {
		return d.Protocol
	}
	return "udp"
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
func (d *Dig) remoteAddr() (string, error) {
	_, _, err := net.SplitHostPort(d.RemoteAddr)
	if err != nil {
		return d.RemoteAddr, errors.New("forget SetDNS ? " + err.Error())
	}
	return d.RemoteAddr, nil
}
func (d *Dig) conn() (net.Conn, error) {
	remoteaddr, err := d.remoteAddr()
	if err != nil {
		return nil, err
	}
	if d.LocalAddr == "" {
		return net.DialTimeout(d.protocol(), remoteaddr, d.dialTimeout())
	}
	return dial(d.protocol(), d.LocalAddr, remoteaddr, d.dialTimeout())
}
func dial(network string, local string, remote string, timeout time.Duration) (net.Conn, error) {
	network = strings.ToLower(network)
	dialer := new(net.Dialer)
	dialer.Timeout = timeout
	local = local + ":0" //端口0,系统会自动分配本机端口
	switch network {
	case "udp":
		addr, err := net.ResolveUDPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	case "tcp":
		addr, err := net.ResolveTCPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	return dialer.Dial(network, remote)
}

func NewMsg(Type uint16, domain string) *dns.Msg {
	return newMsg(Type, domain)
}

func newMsg(Type uint16, domain string) *dns.Msg {
	domain = dns.Fqdn(domain)
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

func (d *Dig) Exchange(m *dns.Msg) (*dns.Msg, error) {
	return d.exchange(m)
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
	d.edns0clientsubnet(m)
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

func (d *Dig) SetTimeOut(t time.Duration) {
	d.ReadTimeout = t
	d.WriteTimeout = t
	d.DialTimeout = t
}

func (d *Dig) SetDNS(host string) error {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			h = host
			port = "53"
			err = nil
		} else {
			return err
		}
	}
	ip, err := net.LookupIP(h)
	if err != nil || len(ip) < 1 {
		if err == nil {
			return errors.New("host can't resolv")
		}
		return err
	}
	d.RemoteAddr = ip[0].String() + ":" + port
	return nil
}

func (d *Dig) SetEDNS0ClientSubnet(clientip string) error {
	ip := net.ParseIP(clientip)
	if ip.To4() == nil {
		return errors.New("not a ipv4")
	}
	d.EDNSSubnet = ip
	return nil
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

func (d *Dig) PTR(domain string) ([]*dns.PTR, error) {
	m := newMsg(dns.TypePTR, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var P []*dns.PTR
	for _, v := range res.Answer {
		if p, ok := v.(*dns.PTR); ok {
			P = append(P, p)
		}
	}
	return P, nil
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

func (d *Dig) AAAA(domain string) ([]*dns.AAAA, error) {
	m := newMsg(dns.TypeAAAA, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	var aaaa []*dns.AAAA
	for _, v := range res.Answer {
		if a, ok := v.(*dns.AAAA); ok {
			aaaa = append(aaaa, a)
		}
	}
	return aaaa, nil
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

func (d *Dig) SRV(domain string) ([]*dns.SRV, error) {
	msg := newMsg(dns.TypeSRV, domain)
	res, err := d.exchange(msg)
	if err != nil {
		return nil, err
	}
	var S []*dns.SRV
	for _, v := range res.Answer {
		if s, ok := v.(*dns.SRV); ok {
			S = append(S, s)
		}
	}
	return S, nil
}

func (d *Dig) CAA(domain string) ([]*dns.CAA, error) {
	msg := newMsg(dns.TypeCAA, domain)
	res, err := d.exchange(msg)
	if err != nil {
		return nil, err
	}
	var C []*dns.CAA
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CAA); ok {
			C = append(C, c)
		}
	}
	return C, nil
}

func (d *Dig) ANY(domain string) ([]dns.RR, error) {
	m := newMsg(dns.TypeANY, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	return res.Answer, nil
}

func (d *Dig) GetRR(Type uint16, domain string) ([]dns.RR, error) {
	m := newMsg(Type, domain)
	res, err := d.exchange(m)
	if err != nil {
		return nil, err
	}
	return res.Answer, nil
}

func (d *Dig) GetMsg(Type uint16, domain string) (*dns.Msg, error) {
	m := newMsg(Type, domain)
	return d.exchange(m)
}

func (d *Dig) edns0clientsubnet(m *dns.Msg) {
	if d.EDNSSubnet == nil {
		return
	}
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,  //ipv4
		SourceNetmask: 32, //ipv4
		Address:       d.EDNSSubnet,
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)
}
