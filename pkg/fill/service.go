package fill

import (
	"math"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/ethereum/go-ethereum/statediff/indexer/postgres"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-server/pkg/serve"
)

// WatchedAddress type is used to process currently watched addresses
type WatchedAddress struct {
	Address      string `db:"address"`
	CreatedAt    uint64 `db:"created_at"`
	WatchedAt    uint64 `db:"watched_at"`
	LastFilledAt uint64 `db:"last_filled_at"`

	StartBlock uint64
	EndBlock   uint64
}

// Service is the underlying struct for the watched address gap filling service
type Service struct {
	db       *postgres.DB
	client   *rpc.Client
	interval int
}

// NewServer creates a new Service
func New(config *serve.Config) *Service {
	return &Service{
		db:       config.DB,
		client:   config.Client,
		interval: config.WatchedAddressGapFillInterval,
	}
}

// Start is used to begin the service
func (s *Service) Start() {
	for {
		time.Sleep(time.Duration(s.interval) * time.Second)

		// Get watched addresses from the db
		rows := s.fetchWatchedAddresses()

		// Get the block number to start fill at
		// Get the block number to end fill at
		fillWatchedAddresses, minStartBlock, maxEndBlock := s.GetFillAddresses(rows)

		if len(fillWatchedAddresses) > 0 {
			log.Infof("running watched address gap filler for block range: (%d, %d)", minStartBlock, maxEndBlock)
		}

		// Fill the missing diffs
		for blockNumber := minStartBlock; blockNumber <= maxEndBlock; blockNumber++ {
			params := statediff.Params{
				IntermediateStateNodes:   true,
				IntermediateStorageNodes: true,
				IncludeBlock:             true,
				IncludeReceipts:          true,
				IncludeTD:                true,
				IncludeCode:              true,
			}

			fillAddresses := []interface{}{}
			for _, fillWatchedAddress := range fillWatchedAddresses {
				if blockNumber >= fillWatchedAddress.StartBlock && blockNumber <= fillWatchedAddress.EndBlock {
					params.WatchedAddresses = append(params.WatchedAddresses, common.HexToAddress(fillWatchedAddress.Address))
					fillAddresses = append(fillAddresses, fillWatchedAddress.Address)
				}
			}

			if len(fillAddresses) > 0 {
				s.writeStateDiffAt(blockNumber, params)
				s.UpdateLastFilledAt(blockNumber, fillAddresses)
			}
		}
	}
}

// GetFillAddresses finds the encompassing range to perform fill for the given watched addresses
// it also sets the address specific fill range
func (s *Service) GetFillAddresses(rows []WatchedAddress) ([]WatchedAddress, uint64, uint64) {
	fillWatchedAddresses := []WatchedAddress{}
	minStartBlock := uint64(math.MaxUint64)
	maxEndBlock := uint64(0)

	for _, row := range rows {
		// Check for a gap between created_at and watched_at
		// CreatedAt and WatchedAt being equal is considered a gap of one block
		if row.CreatedAt > row.WatchedAt {
			continue
		}

		var startBlock uint64 = 0
		var endBlock uint64 = 0

		// Check if some of the gap was filled earlier
		if row.LastFilledAt > 0 {
			if row.LastFilledAt < row.WatchedAt {
				startBlock = row.LastFilledAt + 1
			}
		} else {
			startBlock = row.CreatedAt
		}

		// Add the address for filling
		if startBlock > 0 {
			row.StartBlock = startBlock
			if startBlock < minStartBlock {
				minStartBlock = startBlock
			}

			endBlock = row.WatchedAt
			row.EndBlock = endBlock
			if endBlock > maxEndBlock {
				maxEndBlock = endBlock
			}

			fillWatchedAddresses = append(fillWatchedAddresses, row)
		}
	}

	return fillWatchedAddresses, minStartBlock, maxEndBlock
}

// UpdateLastFilledAt updates the fill status for the provided addresses in the db
func (s *Service) UpdateLastFilledAt(blockNumber uint64, fillAddresses []interface{}) {
	// Prepare the query
	query := "UPDATE eth.watched_addresses SET last_filled_at=? WHERE address IN (?" + strings.Repeat(",?", len(fillAddresses)-1) + ")"
	query = s.db.Rebind(query)

	args := []interface{}{blockNumber}
	args = append(args, fillAddresses...)

	// Execute the update query
	_, err := s.db.Exec(query, args...)
	if err != nil {
		log.Fatalf(err.Error())
	}
}

// fetchWatchedAddresses fetches watched addresses from the db
func (s *Service) fetchWatchedAddresses() []WatchedAddress {
	rows := []WatchedAddress{}
	pgStr := "SELECT * FROM eth.watched_addresses"

	err := s.db.Select(&rows, pgStr)
	if err != nil {
		log.Fatalf("Error fetching watched addreesses: %s", err.Error())
	}

	return rows
}

// writeStateDiffAt makes a RPC call to writeout statediffs at a blocknumber with the given params
func (s *Service) writeStateDiffAt(blockNumber uint64, params statediff.Params) {
	err := s.client.Call(nil, "statediff_writeStateDiffAt", blockNumber, params)
	if err != nil {
		log.Fatalf("Error making a RPC call to write statediff at block number %d: %s", blockNumber, err.Error())
	}
}
