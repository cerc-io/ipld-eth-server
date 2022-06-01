package graphql

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gqlclient "github.com/machinebox/graphql"
)

type StorageResponse struct {
	Cid       string        `json:"cid"`
	Value     common.Hash   `json:"value"`
	IpldBlock hexutil.Bytes `json:"ipldBlock"`
}

type GetStorageAt struct {
	Response StorageResponse `json:"getStorageAt"`
}

type LogResponse struct {
	Topics      []common.Hash   `json:"topics"`
	Data        hexutil.Bytes   `json:"data"`
	Transaction TransactionResp `json:"transaction"`
	ReceiptCID  string          `json:"receiptCID"`
	Status      int32           `json:"status"`
}

type TransactionResp struct {
	Hash common.Hash `json:"hash"`
}

type GetLogs struct {
	Responses []LogResponse `json:"getLogs"`
}

type IPFSBlockResp struct {
	Key  string `json:"key"`
	Data string `json:"data"`
}

type EthTransactionCidResp struct {
	Cid          string        `json:"cid"`
	TxHash       string        `json:"txHash"`
	Index        int32         `json:"index"`
	Src          string        `json:"src"`
	Dst          string        `json:"dst"`
	BlockByMhKey IPFSBlockResp `json:"blockByMhKey"`
}

type EthTransactionCidByTxHash struct {
	Response EthTransactionCidResp `json:"ethTransactionCidByTxHash"`
}

type EthTransactionCidsByHeaderIdResp struct {
	Nodes []EthTransactionCidResp `json:"nodes"`
}

type EthHeaderCidResp struct {
	Cid                          string                           `json:"cid"`
	BlockNumber                  BigInt                           `json:"blockNumber"`
	BlockHash                    string                           `json:"blockHash"`
	ParentHash                   string                           `json:"parentHash"`
	Timestamp                    BigInt                           `json:"timestamp"`
	StateRoot                    string                           `json:"stateRoot"`
	Td                           BigInt                           `json:"td"`
	TxRoot                       string                           `json:"txRoot"`
	ReceiptRoot                  string                           `json:"receiptRoot"`
	UncleRoot                    string                           `json:"uncleRoot"`
	Bloom                        string                           `json:"bloom"`
	EthTransactionCidsByHeaderId EthTransactionCidsByHeaderIdResp `json:"ethTransactionCidsByHeaderId"`
	BlockByMhKey                 IPFSBlockResp                    `json:"blockByMhKey"`
}

type AllEthHeaderCidsResp struct {
	Nodes []EthHeaderCidResp `json:"nodes"`
}

type AllEthHeaderCids struct {
	Response AllEthHeaderCidsResp `json:"allEthHeaderCids"`
}

type Client struct {
	client *gqlclient.Client
}

func NewClient(endpoint string) *Client {
	client := gqlclient.NewClient(endpoint)
	return &Client{client: client}
}

func (c *Client) GetLogs(ctx context.Context, hash common.Hash, address *common.Address) ([]LogResponse, error) {
	params := fmt.Sprintf(`blockHash: "%s"`, hash.String())
	if address != nil {
		params += fmt.Sprintf(`, contract: "%s"`, address.String())
	}

	getLogsQuery := fmt.Sprintf(`query{
			getLogs(%s) {
				data
				topics
				transaction {
					hash
				}
				status
				receiptCID
			}
		}`, params)

	req := gqlclient.NewRequest(getLogsQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var logs GetLogs
	err = json.Unmarshal(jsonStr, &logs)
	if err != nil {
		return nil, err
	}
	return logs.Responses, nil
}

func (c *Client) GetStorageAt(ctx context.Context, hash common.Hash, address common.Address, slot string) (*StorageResponse, error) {
	getLogsQuery := fmt.Sprintf(`
		query{
			getStorageAt(blockHash: "%s", contract: "%s",slot: "%s") {
				cid
				value
				ipldBlock
			}
		}
	`, hash.String(), address.String(), common.HexToHash(slot))

	req := gqlclient.NewRequest(getLogsQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var storageAt GetStorageAt
	err = json.Unmarshal(jsonStr, &storageAt)
	if err != nil {
		return nil, err
	}
	return &storageAt.Response, nil
}

func (c *Client) AllEthHeaderCids(ctx context.Context, condition EthHeaderCidCondition) (*AllEthHeaderCidsResp, error) {
	var params string
	if condition.BlockHash != nil {
		params = fmt.Sprintf(`blockHash: "%s"`, *condition.BlockHash)
	}
	if condition.BlockNumber != nil {
		params += fmt.Sprintf(`blockNumber: "%s"`, condition.BlockNumber.String())
	}

	getHeadersQuery := fmt.Sprintf(`
		query{
			allEthHeaderCids(condition: { %s }) {
				nodes {
					cid
					blockNumber
					blockHash
					parentHash
					timestamp
					stateRoot
					td
					txRoot
					receiptRoot
					uncleRoot
					bloom
					blockByMhKey {
						key
						data
					}
					ethTransactionCidsByHeaderId {
						nodes {
							cid
							txHash
							index
							src
							dst
						}
					}
				}
			}
		}
	`, params)

	req := gqlclient.NewRequest(getHeadersQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var allEthHeaderCids AllEthHeaderCids
	err = json.Unmarshal(jsonStr, &allEthHeaderCids)
	if err != nil {
		return nil, err
	}
	return &allEthHeaderCids.Response, nil
}

func (c *Client) EthTransactionCidByTxHash(ctx context.Context, txHash string) (*EthTransactionCidResp, error) {
	getTxQuery := fmt.Sprintf(`
		query{
			ethTransactionCidByTxHash(txHash: "%s") {
				cid
				txHash
				index
				src
				dst
				blockByMhKey {
					data
				}
			}
		}
	`, txHash)

	req := gqlclient.NewRequest(getTxQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var ethTxCid EthTransactionCidByTxHash
	err = json.Unmarshal(jsonStr, &ethTxCid)
	if err != nil {
		return nil, err
	}
	return &ethTxCid.Response, nil
}
