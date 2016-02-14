package dhcp4

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test dispatch to ReplyWriter
func TestRequestWriteReply(t *testing.T) {
	rw := &testReplyWriter{}

	msg := Request{
		Packet:      NewPacket(BootRequest),
		ReplyWriter: rw,
	}

	reps := []Reply{
		CreateAck(msg),
		CreateNak(msg),
	}

	for _, rep := range reps {
		rw.wrote = false
		msg.WriteReply(rep)
		assert.True(t, rw.wrote)
	}
}
