package dhcp4

// Inform is a client to server packet, asking only for local configuration
// parameters; client already has externally configured network address.
type Inform struct {
	Packet
	ReplyWriter
}
