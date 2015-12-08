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
package dhcpv4

import "encoding/binary"

// Nak is a server to client packet indicating client's notion of network
// address is incorrect (e.g., client has moved to new subnet) or client's
// lease as expired.
type Nak struct {
	Packet

	msg Message
}

func CreateNak(msg Message) Nak {
	rep := Nak{
		Packet: NewReply(msg),
		msg:    msg,
	}

	rep.SetMessageType(MessageTypeNak)
	return rep
}

// From RFC2131, table 3:
//   Option                    DHCPNAK
//   ------                    -------
//   Requested IP address      MUST NOT
//   IP address lease time     MUST NOT
//   Use 'file'/'sname' fields MUST NOT
//   DHCP message type         DHCPNAK
//   Parameter request list    MUST NOT
//   Message                   SHOULD
//   Client identifier         MAY
//   Vendor class identifier   MAY
//   Server identifier         MUST
//   Maximum message size      MUST NOT
//   All others                MUST NOT

var dhcpNakAllowedOptions = []Option{
	OptionDHCPMsgType,
	OptionDHCPMessage,
	OptionClientID,
	OptionClassID,
	OptionDHCPServerID,
}

var dhcpNakValidation = []Validation{
	ValidateMust(OptionDHCPServerID),
	ValidateAllowedOptions(dhcpNakAllowedOptions),
}

func (d Nak) Validate() error {
	return Validate(d.Packet, dhcpNakValidation)
}

func (d Nak) ToBytes() ([]byte, error) {
	opts := packetToBytesOptions{
		skipFile:  true,
		skipSName: true,
	}

	// Copy MaxMsgSize if set in the request
	if v, ok := d.Message().GetOption(OptionDHCPMaxMsgSize); ok {
		opts.maxLen = binary.BigEndian.Uint16(v)
	}

	return PacketToBytes(d.Packet, &opts)
}

func (d Nak) Message() Message {
	return d.msg
}
