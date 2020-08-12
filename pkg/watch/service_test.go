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

package watch_test

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/eth/mocks"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/shared"
	mocks2 "github.com/vulcanize/ipfs-blockchain-watcher/pkg/shared/mocks"
	"github.com/vulcanize/ipfs-blockchain-watcher/pkg/watch"
)

var _ = Describe("Service", func() {
	Describe("Sync", func() {
		It("Streams statediff.Payloads, converts them to IPLDPayloads, publishes IPLDPayloads, and indexes CIDPayloads", func() {
			wg := new(sync.WaitGroup)
			payloadChan := make(chan shared.RawChainData, 1)
			quitChan := make(chan bool, 1)
			mockPublisher := &mocks.IPLDPublisher{
				ReturnCIDPayload: mocks.MockCIDPayload,
				ReturnErr:        nil,
			}
			mockStreamer := &mocks2.PayloadStreamer{
				ReturnSub: &rpc.ClientSubscription{},
				StreamPayloads: []shared.RawChainData{
					mocks.MockStateDiffPayload,
				},
				ReturnErr: nil,
			}
			mockConverter := &mocks.PayloadConverter{
				ReturnIPLDPayload: mocks.MockConvertedPayload,
				ReturnErr:         nil,
			}
			processor := &watch.Service{
				Publisher:      mockPublisher,
				Streamer:       mockStreamer,
				Converter:      mockConverter,
				PayloadChan:    payloadChan,
				QuitChan:       quitChan,
				WorkerPoolSize: 1,
			}
			err := processor.Sync(wg, nil)
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(2 * time.Second)
			close(quitChan)
			wg.Wait()
			Expect(mockConverter.PassedStatediffPayload).To(Equal(mocks.MockStateDiffPayload))
			Expect(mockPublisher.PassedIPLDPayload).To(Equal(mocks.MockConvertedPayload))
			Expect(mockStreamer.PassedPayloadChan).To(Equal(payloadChan))
		})
	})
})
