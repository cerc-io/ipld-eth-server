// VulcanizeDB
// Copyright © 2021 Vulcanize

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

package net_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/vulcanize/ipld-eth-server/v3/pkg/net"
)

var _ = Describe("API", func() {
	var (
		api *net.PublicNetAPI
	)
	BeforeEach(func() {
		api = net.NewPublicNetAPI(1, nil)
	})
	Describe("net_listening", func() {
		It("Retrieves whether or not the node is listening to the p2p network", func() {
			listening := api.Listening()
			Expect(listening).To(BeFalse())
		})
	})

	Describe("net_version", func() {
		It("Retrieves the network id", func() {
			version := api.Version()
			Expect(version).To(Equal("1"))
		})
	})
	// TODO: test PeerCount with mock proxy node
})
