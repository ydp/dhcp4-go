package dhcp4

import "testing"

func TestOfferValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			return &Offer{
				Packet: NewPacket(BootReply),
				msg:    NewPacket(BootRequest),
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
