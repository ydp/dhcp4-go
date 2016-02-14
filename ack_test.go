package dhcp4

import "testing"

func TestAckOnRequestValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			msg := NewPacket(BootRequest)
			msg.SetMessageType(MessageTypeRequest)
			return &Ack{
				Packet: NewPacket(BootReply),
				msg:    msg,
			}
		},
		must: []Option{
			OptionAddressTime,
			OptionDHCPServerID,
		},
		mustNot: []Option{
			OptionAddressRequest,
			OptionParameterList,
			OptionClientID,
			OptionDHCPMaxMsgSize,
		},
	}

	testCase.Test(t)
}

func TestAckOnInformValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			msg := NewPacket(BootRequest)
			msg.SetMessageType(MessageTypeInform)
			return &Ack{
				Packet: NewPacket(BootReply),
				msg:    msg,
			}
		},
		must: []Option{
			OptionDHCPServerID,
		},
		mustNot: []Option{
			OptionAddressRequest,
			OptionAddressTime,
			OptionParameterList,
			OptionClientID,
			OptionDHCPMaxMsgSize,
		},
	}

	testCase.Test(t)
}
