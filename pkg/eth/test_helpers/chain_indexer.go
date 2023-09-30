package test_helpers

import (
	"context"
	"math/big"

	"github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/shared"
)

type IndexChainParams struct {
	Blocks      []*types.Block
	Receipts    []types.Receipts
	StateCache  state.Database
	ChainConfig *params.ChainConfig

	StateDiffParams statediff.Params
	TotalDifficulty *big.Int
	// Whether to skip indexing state nodes (state_cids, storage_cids)
	SkipStateNodes bool
	// Whether to skip indexing IPLD blocks
	SkipIPLDs bool
}

func IndexChain(params IndexChainParams) error {
	indexer := shared.SetupTestStateDiffIndexer(context.Background(), params.ChainConfig, Genesis.Hash())
	builder := statediff.NewBuilder(adapt.GethStateView(params.StateCache))
	// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
	for i, block := range params.Blocks {
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
				OldStateRoot: params.Blocks[i-1].Root(),
				NewStateRoot: block.Root(),
				BlockNumber:  block.Number(),
				BlockHash:    block.Hash(),
			}
			rcts = params.Receipts[i-1]
		}

		diff, err := builder.BuildStateDiffObject(args, params.StateDiffParams)
		if err != nil {
			return err
		}
		tx, err := indexer.PushBlock(block, rcts, params.TotalDifficulty)
		if err != nil {
			return err
		}
		defer tx.RollbackOnFailure(err)

		if !params.SkipStateNodes {
			for _, node := range diff.Nodes {
				if err = indexer.PushStateNode(tx, node, block.Hash().String()); err != nil {
					return err
				}
			}
		}
		if !params.SkipIPLDs {
			for _, ipld := range diff.IPLDs {
				if err := indexer.PushIPLD(tx, ipld); err != nil {
					return err
				}
			}
		}
		if err = tx.Submit(); err != nil {
			return err
		}
	}
	return nil
}
