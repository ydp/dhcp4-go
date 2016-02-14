package dhcp4

// Message
type Message interface {
	PacketGetter
	OptionGetter

	// Every request can tell where it came from.
	InterfaceIndex() int
}

// Reply defines an interface implemented by DHCP replies.
type Reply interface {
	Validate() error
	ToBytes() ([]byte, error)
	Message() Message

	PacketSetter
	OptionSetter
}

// ReplyWriter defines an interface for the object that writes a reply to the
// network to the intended received, be it via broadcast or unicast.
type ReplyWriter interface {
	WriteReply(r Reply) error
}
