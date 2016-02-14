package dhcp4

import "testing"

func TestNakValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			msg := NewPacket(BootRequest)
			return &Nak{
				Packet: NewPacket(BootReply),
				msg:    &msg,
			}
		},
		must: []Option{
			OptionDHCPServerID,
		},
		mustNot: []Option{
			OptionAddressRequest,
			OptionAddressTime,

			// Some random options that are not called out explicitly,
			// to test the deny-by-default policy.
			OptionPXEUndefined128,
			OptionPXEUndefined129,
		},
	}

	testCase.Test(t)
}
