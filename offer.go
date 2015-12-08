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

// Offer is a server to client packet in response to DHCPDISCOVER with
// offer of configuration parameters.
type Offer struct {
	Packet

	msg Message
}

func CreateOffer(msg Message) Offer {
	rep := Offer{
		Packet: NewReply(msg),
		msg:    msg,
	}

	rep.SetMessageType(MessageTypeOffer)
	return rep
}

// From RFC2131, table 3:
//   Option                    DHCPOFFER
//   ------                    ---------
//   Requested IP address      MUST NOT
//   IP address lease time     MUST
//   Use 'file'/'sname' fields MAY
//   DHCP message type         DHCPOFFER
//   Parameter request list    MUST NOT
//   Message                   SHOULD
//   Client identifier         MUST NOT
//   Vendor class identifier   MAY
//   Server identifier         MUST
//   Maximum message size      MUST NOT
//   All others                MAY

var dhcpOfferValidation = []Validation{
	ValidateMustNot(OptionAddressRequest),
	ValidateMust(OptionAddressTime),
	ValidateMustNot(OptionParameterList),
	ValidateMustNot(OptionClientID),
	ValidateMust(OptionDHCPServerID),
	ValidateMustNot(OptionDHCPMaxMsgSize),
}

func (d Offer) Validate() error {
	return Validate(d.Packet, dhcpOfferValidation)
}

func (d Offer) ToBytes() ([]byte, error) {
	opts := packetToBytesOptions{}

	// Copy MaxMsgSize if set in the request
	if v, ok := d.Message().GetOption(OptionDHCPMaxMsgSize); ok {
		opts.maxLen = binary.BigEndian.Uint16(v)
	}

	return PacketToBytes(d.Packet, &opts)
}

func (d Offer) Message() Message {
	return d.msg
}
