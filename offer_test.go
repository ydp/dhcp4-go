package dhcp4

import "testing"

func TestOfferValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			msg := NewPacket(BootRequest)
			return &Offer{
				Packet: NewPacket(BootReply),
				msg:    &msg,
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
