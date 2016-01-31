/*
Copyright (c) 2014 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
