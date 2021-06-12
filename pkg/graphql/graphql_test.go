// VulcanizeDB
// Copyright © 2020 Vulcanize

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

package graphql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	_ "github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	shurcool_graphql "github.com/shurcooL/graphql"
	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"
	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
	"github.com/vulcanize/ipld-eth-server/pkg/graphql"
	"golang.org/x/oauth2"
)

var _ = Describe("GraphQL", func() {
	var (
		blocks   []*types.Block
		receipts []types.Receipts
		chain    *core.BlockChain
		db       *postgres.DB
		//api                     *eth.PublicEthAPI
		backend     *eth.Backend
		chainConfig = params.TestChainConfig
		mockTD      = big.NewInt(1337)
	)
	It("Builds the schema and creates a new handler", func() {

		fmt.Println("TEST testgraphql.....")
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		transformer := eth2.NewStateDiffTransformer(chainConfig, db)
		backend, err = eth.NewEthBackend(db, &eth.Config{
			ChainConfig: chainConfig,
			VmConfig:    vm.Config{},
			RPCGasCap:   big.NewInt(10000000000),
		})
		Expect(err).ToNot(HaveOccurred())

		//api = eth.NewPublicEthAPI(backend, nil, false)

		// make the test blockchain (and state)
		blocks, receipts, chain = test_helpers.MakeChain(5, test_helpers.Genesis, test_helpers.TestChainGen)
		params := statediff.Params{
			IntermediateStateNodes:   true,
			IntermediateStorageNodes: true,
		}

		// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
		builder := statediff.NewBuilder(chain.StateCache())
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
			diff, err := builder.BuildStateDiffObject(args, params)
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

		// Insert some non-canonical data into the database so that we test our ability to discern canonicity
		indexAndPublisher := eth2.NewIPLDPublisher(db)
		//api = eth.NewPublicEthAPI(backend, nil, false)
		fmt.Println("BHash:", test_helpers.MockBlock.Hash())
		blockHash := test_helpers.MockBlock.Hash()
		fmt.Println("contractHash:", test_helpers.ContractAddr)
		contractAddress := test_helpers.ContractAddr
		fmt.Println("ContractSlotPosition:", common.BytesToHash(test_helpers.ContractSlotPosition))
		//slot:=common.BytesToHash(test_helpers.ContractSlotPosition)

		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayload)
		Expect(err).ToNot(HaveOccurred())
		// The non-canonical header has a child
		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayloadForChild)
		Expect(err).ToNot(HaveOccurred())
		err = publishCode(db, test_helpers.ContractCodeHash, test_helpers.ContractCode)
		Expect(err).ToNot(HaveOccurred())

		fmt.Println("", backend)
		_, err = graphql.NewHandler(backend)

		endPoint := "127.0.0.1:8083"

		graphQLServer, err := graphql.New(backend, endPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})

		if err != nil {
			return
		}

		go graphQLServer.Start(nil)
		/*
				getLogs(blockHash: "0xe80fd93b2ffd9cfbe2e0e0cf03c07aabb66657823713a51981a6bffed443c98f", contract: "0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476592") {
					cid
					data
					index
					topics
					ipldBlock
				}
			}
		*/

		src := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: os.Getenv("GRAPHQL_TOKEN")},
		)
		fmt.Println("AccessToken:", os.Getenv("GRAPHQL_TOKEN"))

		httpClient := oauth2.NewClient(context.Background(), src)

		graphql_client := shurcool_graphql.NewClient("http://localhost:8083/graphql/", httpClient)

		var q struct {
			Logs struct {
				Topics []common.Hash
			} `graphql:"getLogs(blockHash: $blockHash ,contract: $contractAddress )"`
		}

		variables := map[string]interface{}{
			"blockHash":       blockHash,
			"contractAddress": contractAddress,
		}
		fmt.Println("VARIABLE: ", variables)
		// Use client...
		err = graphql_client.Query(context.Background(), &q, variables)
		if err != nil {
			fmt.Println("errored out", err)

		}
		//fmt.Println(q.Logs.cid)
		fmt.Println("Index:", q.Logs)
		//fmt.Println("Data: ", q.Logs.data)

		//Make Request
		var jsonData = map[string]string{
			"query": "" +
				"{" +
				"getLogs(blockHash: \"" + fmt.Sprintf("%s", blockHash) + "\", contract: \"" + fmt.Sprintf("%s", contractAddress) + "\") {" +
				"\ncid" +
				"\ndata" +
				"\nindex" +
				"\ntopics" +
				"\nipldBlock" +
				"}" +
				"}",
		}
		fmt.Println("jsonData:", jsonData)

		jsonValue, _ := json.Marshal(jsonData)
		request, err := http.NewRequest("POST", "http://localhost:8083/graphql/", bytes.NewBuffer(jsonValue))
		client := &http.Client{Timeout: time.Second * 10}
		response, err := client.Do(request)
		//defer response.Body.Close()
		if err != nil {
			fmt.Printf("The HTTP request failed with error %s\n", err)
		}
		data, _ := ioutil.ReadAll(response.Body)
		fmt.Println(string(data))

		shutdown := make(chan os.Signal)
		signal.Notify(shutdown, os.Interrupt)
		<-shutdown

		fmt.Println("Below Channel...")
		//time.Sleep(1000 * time.Second)
	})
})

func publishCode(db *postgres.DB, codeHash common.Hash, code []byte) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	mhKey, err := shared.MultihashKeyFromKeccak256(codeHash)
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := shared.PublishDirect(tx, mhKey, code); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
