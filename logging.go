package dhcp4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/pkg/capnslog"
)

var clog = capnslog.NewPackageLogger("github.com/betawaffle/dhcp4-go", "dhcp")

var optionFormats = map[Option]func([]byte) string{
	OptionDHCPMsgType:    nil,
	OptionDHCPMaxMsgSize: nil, // func(b []byte) string { return fmt.Sprintf("max-msg-size=%d", binary.BigEndian.Uint16(b)) },
	OptionParameterList:  nil, // func(b []byte) string { return "param-list=..." }
	OptionClientID:       func(b []byte) string { return "client-id=" + formatHex(b) },
	OptionClientNDI:      func(b []byte) string { return "client-ndi=" + formatNDI(b) },
	OptionDHCPServerID:   func(b []byte) string { return "dhcp-server=" + net.IP(b).String() },
	OptionDomainServer:   func(b []byte) string { return "dns=" + formatIP(b) },
	OptionHostname:       func(b []byte) string { return "hostname=" + string(b) },
	OptionAddressRequest: func(b []byte) string { return "requested-ip=" + net.IP(b).String() },
	OptionAddressTime:    func(b []byte) string { return "lease-time=" + formatSeconds(b) },
	OptionSubnetMask:     func(b []byte) string { return "netmask=" + net.IP(b).String() },
	OptionRouter:         func(b []byte) string { return "routers=" + formatIP(b) },
	OptionLogServer:      func(b []byte) string { return "syslog=" + formatIP(b) },
	OptionUUIDGUID:       func(b []byte) string { return "uuid=" + formatUUID(b[1:]) },
	OptionVendorSpecific: func(b []byte) string { return "vendor-specific=" + formatHex(b) },
	OptionClassID:        func(b []byte) string { return fmt.Sprintf("class-id=%q", b) },
	OptionClientSystem:   func(b []byte) string { return fmt.Sprintf("client-arch=%d", binary.BigEndian.Uint16(b)) },
	OptionDHCPMessage:    func(b []byte) string { return fmt.Sprintf("msg=%q", b) },
	OptionUserClass:      func(b []byte) string { return fmt.Sprintf("user-class=%q", b) },
}

func SetOptionFormatter(o Option, fn func([]byte) string) {
	optionFormats[o] = fn
}

func formatOptions(om OptionMap) string {
	fields := make([]string, 0, len(om))

	for o, b := range om {
		fn, ok := optionFormats[o]
		if !ok {
			fields = append(fields, fmt.Sprintf("option(%d)=%q", o, b))
			continue
		}
		if fn == nil {
			continue
		}
		fields = append(fields, fn(b))
	}
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

func formatHex(b []byte) string {
	buf := append(make([]byte, 0, len(b)*2+len(b)+2), '"')
	for i, c := range b {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = strconv.AppendUint(buf, uint64(c), 16) // FIXME
	}
	buf = append(buf, '"')
	return string(buf)
}

func formatIP(b []byte) string {
	if len(b)%4 != 0 {
		return fmt.Sprintf("%q", b)
	}
	ips := make([]string, 0, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		ips = append(ips, net.IP(b[i:i+4]).String())
	}
	return strings.Join(ips, ",")
}

func formatNDI(b []byte) string {
	if len(b) != 3 {
		return formatHex(b)
	}
	if t := b[0]; t == 1 {
		return fmt.Sprintf("UNDI-%d.%d", b[1], b[2])
	}
	return fmt.Sprintf("%d-%d.%d", b[0], b[1], b[2])
}

func formatSeconds(b []byte) string {
	var (
		secs = binary.BigEndian.Uint32(b)
		dur  = time.Duration(secs) * time.Second
	)
	return dur.String()
}

func formatUUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type serverRecv struct {
	msg     *Packet
	ip      net.IP
	ifindex int
}

func (sr *serverRecv) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("received ")
	buf.WriteString(sr.msg.GetMessageType().String())
	buf.WriteString(" from ")
	buf.WriteString(sr.msg.GetCHAddr().String())
	buf.WriteString(" via ")
	buf.WriteString(sr.ip.String())

	if sr.msg.GetGIAddr().Equal(sr.ip) {
		buf.WriteString(" (gateway)")
	}

	if iface, err := net.InterfaceByIndex(sr.ifindex); err == nil {
		buf.WriteString(" over ")
		buf.WriteString(iface.Name)
	}

	writeOptions(buf, sr.msg.OptionMap)

	return buf.String()
}

type serverSend struct {
	req     *Packet
	rep     *Packet
	ip      net.IP
	ifindex int
}

func (ss *serverSend) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("sending ")
	buf.WriteString(ss.rep.GetMessageType().String())
	buf.WriteString(" to ")
	buf.WriteString(ss.req.GetCHAddr().String())
	buf.WriteString(" via ")
	buf.WriteString(ss.ip.String())

	if ss.req.GetGIAddr().Equal(ss.ip) {
		buf.WriteString(" (gateway)")
	}

	if iface, err := net.InterfaceByIndex(ss.ifindex); err == nil {
		buf.WriteString(" over ")
		buf.WriteString(iface.Name)
	}

	writeOptions(buf, ss.rep.OptionMap)

	return buf.String()
}

func writeOptions(buf *bytes.Buffer, om OptionMap) {
	// TODO: Figure out how best to sort these.
	for o, b := range om {
		fn, ok := optionFormats[o]
		if !ok {
			fmt.Fprintf(buf, " option(%d)=%q", o, b)
			continue
		}
		if fn == nil {
			continue
		}
		if s := fn(b); s != "" {
			buf.WriteByte(' ')
			buf.WriteString(s)
		}
	}
}
