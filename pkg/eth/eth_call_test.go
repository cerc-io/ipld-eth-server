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

package eth_test

import (
	"bytes"
	"context"
	"io/ioutil"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var (
	parsedABI abi.ABI
)

func init() {
	// load abi
	abiBytes, err := ioutil.ReadFile("./test_helpers/abi.json")
	if err != nil {
		panic(err)
	}
	parsedABI, err = abi.JSON(bytes.NewReader(abiBytes))
	if err != nil {
		panic(err)
	}
}

var _ = Describe("eth_call", func() {
	var (
		blocks      []*types.Block
		receipts    []types.Receipts
		chain       *core.BlockChain
		db          *postgres.DB
		transformer *eth2.StateDiffTransformer
		backend     *eth.Backend
		api         *eth.PublicEthAPI
		builder     statediff.Builder
		pams        statediff.Params
		chainConfig = params.TestChainConfig
		mockTD      = big.NewInt(1337)
	)

	BeforeEach(func() {
		// db and type initializations
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		transformer = eth2.NewStateDiffTransformer(chainConfig, db)
		backend, err = eth.NewEthBackend(db, &eth.Config{
			ChainConfig: chainConfig,
			VmConfig:    vm.Config{},
			RPCGasCap:   big.NewInt(10000000000),
		})
		Expect(err).ToNot(HaveOccurred())
		api = eth.NewPublicEthAPI(backend)

		// make the test blockchain (and state)
		blocks, receipts, chain = test_helpers.MakeChain(4, test_helpers.Genesis, test_helpers.TestChainGen)
		pams = statediff.Params{
			IntermediateStateNodes:   true,
			IntermediateStorageNodes: true,
		}
		// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
		builder = statediff.NewBuilder(chain.StateCache())
		for i, block := range blocks {
			var args statediff.Args
			var rcts types.Receipts
			if i == 0 {
				args = statediff.Args{
					OldStateRoot: common.Hash{},
					NewStateRoot: block.Root(),
					BlockNumber:  block.Number(),
					BlockHash:    block.Hash(),
				}
			} else {
				args = statediff.Args{
					OldStateRoot: blocks[i-1].Root(),
					NewStateRoot: block.Root(),
					BlockNumber:  block.Number(),
					BlockHash:    block.Hash(),
				}
				rcts = receipts[i-1]
			}
			diff, err := builder.BuildStateDiffObject(args, pams)
			Expect(err).ToNot(HaveOccurred())
			diffRlp, err := rlp.EncodeToBytes(diff)
			Expect(err).ToNot(HaveOccurred())
			blockRlp, err := rlp.EncodeToBytes(block)
			Expect(err).ToNot(HaveOccurred())
			receiptsRlp, err := rlp.EncodeToBytes(rcts)
			Expect(err).ToNot(HaveOccurred())
			payload := statediff.Payload{
				StateObjectRlp:  diffRlp,
				BlockRlp:        blockRlp,
				ReceiptsRlp:     receiptsRlp,
				TotalDifficulty: mockTD,
			}
			_, err = transformer.Transform(0, payload)
			Expect(err).ToNot(HaveOccurred())
		}
	})
	AfterEach(func() {
		eth.TearDownDB(db)
		chain.Stop()
	})
	Describe("eth_call", func() {
		It("Applies call args (tx data) on top of state, returning the result (e.g. a Getter method call)", func() {
			data, err := parsedABI.Pack("data")
			Expect(err).ToNot(HaveOccurred())
			bdata := hexutil.Bytes(data)
			callArgs := eth.CallArgs{
				To:   &test_helpers.ContractAddr,
				Data: &bdata,
			}
			res, err := api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(2), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes := hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(3), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(4), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000009"))
			Expect(res).To(Equal(expectedRes))
		})
	})
})
