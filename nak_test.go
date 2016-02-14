package dhcp4

import "testing"

func TestNakValidation(t *testing.T) {
	testCase := replyValidationTestCase{
		newReply: func() ValidatingReply {
			return &Nak{
				Packet: NewPacket(BootReply),
				msg:    NewPacket(BootRequest),
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
