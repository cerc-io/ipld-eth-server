// VulcanizeDB
// Copyright © 2019 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mocks

import (
	"fmt"

	"github.com/vulcanize/ipld-eth-server/pkg/shared"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
)

// IPLDPublisher is the underlying struct for the Publisher interface
type IPLDPublisher struct {
	PassedIPLDPayload eth.ConvertedPayload
	ReturnCIDPayload  *eth.CIDPayload
	ReturnErr         error
}

// Publish publishes an IPLDPayload to IPFS and returns the corresponding CIDPayload
func (pub *IPLDPublisher) Publish(payload shared.ConvertedData) error {
	ipldPayload, ok := payload.(eth.ConvertedPayload)
	if !ok {
		return fmt.Errorf("publish expected payload type %T got %T", &eth.ConvertedPayload{}, payload)
	}
	pub.PassedIPLDPayload = ipldPayload
	return pub.ReturnErr
}

// IterativeIPLDPublisher is the underlying struct for the Publisher interface; used in testing
type IterativeIPLDPublisher struct {
	PassedIPLDPayload []eth.ConvertedPayload
	ReturnCIDPayload  []*eth.CIDPayload
	ReturnErr         error
	iteration         int
}

// Publish publishes an IPLDPayload to IPFS and returns the corresponding CIDPayload
func (pub *IterativeIPLDPublisher) Publish(payload shared.ConvertedData) error {
	ipldPayload, ok := payload.(eth.ConvertedPayload)
	if !ok {
		return fmt.Errorf("publish expected payload type %T got %T", &eth.ConvertedPayload{}, payload)
	}
	pub.PassedIPLDPayload = append(pub.PassedIPLDPayload, ipldPayload)
	pub.iteration++
	return pub.ReturnErr
}
