package dhcp4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test dispatch to ReplyWriter
func TestDiscoverWriteReply(t *testing.T) {
	rw := &testReplyWriter{}

	msg := Discover{
		Packet:      NewPacket(BootRequest),
		ReplyWriter: rw,
	}

	reps := []Reply{
		CreateOffer(msg),
	}

	for _, rep := range reps {
		rw.wrote = false
		msg.WriteReply(rep)
		assert.True(t, rw.wrote)
	}
}
