package dhcp4

// Discover is a client broadcast packet to locate available servers.
type Discover struct {
	Packet
	ReplyWriter
}
