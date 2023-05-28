package integration_test

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

func waitForBlock(ctx context.Context, client *ethclient.Client, target int64) error {
	timeout := 10 * time.Second
	for {
		select {
		case <-time.After(timeout):
			return errors.New("timed out")
		default:
			latest, err := client.BlockNumber(ctx)
			if err != nil {
				return err
			}
			if uint64(target) <= latest {
				return nil
			}
			time.Sleep(time.Second)
		}
	}

}
