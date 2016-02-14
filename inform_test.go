package dhcp4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test dispatch to ReplyWriter
func TestInformWriteReply(t *testing.T) {
	rw := &testReplyWriter{}

	msg := Inform{
		Packet:      NewPacket(BootRequest),
		ReplyWriter: rw,
	}

	reps := []Reply{
		CreateAck(msg),
	}

	for _, rep := range reps {
		rw.wrote = false
		msg.WriteReply(rep)
		assert.True(t, rw.wrote)
	}
}
