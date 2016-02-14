package dhcp4

// Request is a client message to servers either (a) requesting offered
// parameters from one server and implicitly declining offers from all others,
// (b) confirming correctness of previously allocated address after, e.g.,
// system reboot, or (c) extending the lease on a particular network address.
type Request struct {
	Packet
	ReplyWriter
}
