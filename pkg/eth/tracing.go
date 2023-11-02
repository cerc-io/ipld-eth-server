package eth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	ipld_direct_state "github.com/cerc-io/ipld-eth-statedb/direct_by_leaf"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// defaultTraceTimeout is the amount of time a single transaction can execute
	// by default before being forcefully aborted.
	defaultTraceTimeout = 5 * time.Second
)

// TracingAPI is the collection of tracing APIs exposed over the private debugging endpoint.
type TracingAPI struct {
	backend *Backend
	rpc     *rpc.Client
	config  APIConfig
}

// NewTracingAPI creates a new TracingAPI with the provided underlying Backend
func NewTracingAPI(b *Backend, client *rpc.Client, config APIConfig) (*TracingAPI, error) {
	if b == nil {
		return nil, errors.New("ipld-eth-server must be configured with an ethereum backend")
	}
	if config.ForwardEthCalls && client == nil {
		return nil, errors.New("ipld-eth-server is configured to forward eth_calls to proxy node but no proxy node is configured")
	}
	if config.ForwardGetStorageAt && client == nil {
		return nil, errors.New("ipld-eth-server is configured to forward eth_getStorageAt to proxy node but no proxy node is configured")
	}
	if config.ProxyOnError && client == nil {
		return nil, errors.New("ipld-eth-server is configured to forward all calls to proxy node on errors but no proxy node is configured")
	}
	return &TracingAPI{
		backend: b,
		rpc:     client,
		config:  config,
	}, nil
}

// TraceConfig holds extra parameters to trace functions.
type TraceConfig struct {
	*logger.Config
	Tracer  *string
	Timeout *string
	Reexec  *uint64
	// Config specific to given tracer. Note struct logger
	// config are historically embedded in main object.
	TracerConfig json.RawMessage
}

// TraceCallConfig is the config for traceCall API. It holds one more
// field to override the state for tracing.
type TraceCallConfig struct {
	TraceConfig
	StateOverrides *StateOverride
	BlockOverrides *BlockOverrides
}

// TraceCall lets you trace a given eth_call. It collects the structured logs
// created during the execution of EVM if the given transaction was added on
// top of the provided block and returns them as a JSON object.
func (api *TracingAPI) TraceCall(ctx context.Context, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, config *TraceCallConfig) (interface{}, error) {
	trace, err := api.localTraceCall(ctx, args, blockNrOrHash, config)
	if trace != nil && err == nil {
		return trace, nil
	}
	if api.config.ProxyOnError {
		var res interface{}
		if err := api.rpc.CallContext(ctx, &res, "debug_traceCall", args, blockNrOrHash, config); res != nil && err == nil {
			return res, nil
		}
	}
	return nil, err
}

func (api *TracingAPI) localTraceCall(ctx context.Context, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, config *TraceCallConfig) (interface{}, error) {
	// Try to retrieve the specified block
	var (
		err   error
		block *types.Block
	)
	if hash, ok := blockNrOrHash.Hash(); ok {
		block, err = api.blockByHash(ctx, hash)
	} else if number, ok := blockNrOrHash.Number(); ok {
		if number == rpc.PendingBlockNumber {
			// We don't have access to the miner here. For tracing 'future' transactions,
			// it can be done with block- and state-overrides instead, which offers
			// more flexibility and stability than trying to trace on 'pending', since
			// the contents of 'pending' is unstable and probably not a true representation
			// of what the next actual block is likely to contain.
			return nil, errors.New("tracing on top of pending is not supported")
		}
		block, err = api.blockByNumber(ctx, number)
	} else {
		return nil, errors.New("invalid arguments; neither block nor hash specified")
	}
	if err != nil {
		return nil, err
	}

	stateDB, _, err := api.backend.IPLDDirectStateDBAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(block.Hash(), true))
	if err != nil {
		return nil, err
	}
	vmctx := core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
	// Apply the customization rules if required.
	if config != nil {
		if err := config.StateOverrides.Apply(stateDB); err != nil {
			return nil, err
		}
		config.BlockOverrides.Apply(&vmctx)
	}
	// Execute the trace
	msg, err := args.ToMessage(api.backend.RPCGasCap(), block.BaseFee())
	if err != nil {
		return nil, err
	}

	var traceConfig *TraceConfig
	if config != nil {
		traceConfig = &config.TraceConfig
	}
	return api.traceTx(ctx, msg, new(tracers.Context), vmctx, stateDB, traceConfig)
}

// traceTx configures a new tracer according to the provided configuration, and
// executes the given message in the provided environment. The return value will
// be tracer dependent.
func (api *TracingAPI) traceTx(ctx context.Context, message *core.Message, txctx *tracers.Context, vmctx vm.BlockContext, statedb *ipld_direct_state.StateDB, config *TraceConfig) (interface{}, error) {
	var (
		tracer    tracers.Tracer
		err       error
		timeout   = defaultTraceTimeout
		txContext = core.NewEVMTxContext(message)
	)
	if config == nil {
		config = &TraceConfig{}
	}
	// Default tracer is the struct logger
	tracer = logger.NewStructLogger(config.Config)
	if config.Tracer != nil {
		tracer, err = tracers.DefaultDirectory.New(*config.Tracer, txctx, config.TracerConfig)
		if err != nil {
			return nil, err
		}
	}
	vmenv := vm.NewEVM(vmctx, txContext, statedb, api.backend.ChainConfig(), vm.Config{Tracer: tracer, NoBaseFee: true})

	// Define a meaningful timeout of a single transaction trace
	if config.Timeout != nil {
		if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
			return nil, err
		}
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	go func() {
		<-deadlineCtx.Done()
		if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
			tracer.Stop(errors.New("execution timeout"))
			// Stop evm execution. Note cancellation is not necessarily immediate.
			vmenv.Cancel()
		}
	}()
	defer cancel()

	// Call Prepare to clear out the statedb access list
	statedb.SetTxContext(txctx.TxHash, txctx.TxIndex)
	if _, err = core.ApplyMessage(vmenv, message, new(core.GasPool).AddGas(message.GasLimit)); err != nil {
		return nil, fmt.Errorf("tracing failed: %w", err)
	}
	return tracer.GetResult()
}

// chainContext constructs the context reader which is used by the evm for reading
// the necessary chain context.
func (api *TracingAPI) chainContext(ctx context.Context) core.ChainContext {
	return &chainContext{api: api, ctx: ctx}
}

// blockByNumber is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func (api *TracingAPI) blockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	block, err := api.backend.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}
	return block, nil
}

// blockByHash is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func (api *TracingAPI) blockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	block, err := api.backend.BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block %s not found", hash.Hex())
	}
	return block, nil
}

// txTraceTask represents a single transaction trace task when an entire block
// is being traced.
type txTraceTask struct {
	statedb *ipld_direct_state.StateDB // Intermediate state prepped for tracing
	index   int                        // Transaction offset in the block
}

// txTraceResult is the result of a single transaction trace.
type txTraceResult struct {
	Result interface{} `json:"result,omitempty"` // Trace results produced by the tracer
	Error  string      `json:"error,omitempty"`  // Trace failure produced by the tracer
}

// TraceBlockByNumber returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *TracingAPI) TraceBlockByNumber(ctx context.Context, number rpc.BlockNumber, config *TraceConfig) ([]*txTraceResult, error) {
	block, err := api.blockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	trace, err := api.traceBlock(ctx, block, config)
	if trace != nil && err == nil {
		return trace, nil
	}
	if api.config.ProxyOnError {
		var res []*txTraceResult
		if err := api.rpc.CallContext(ctx, &res, "debug_traceBlockByNumber", number, config); res != nil && err == nil {
			return res, nil
		}
	}
	return nil, err
}

// TraceBlockByHash returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *TracingAPI) TraceBlockByHash(ctx context.Context, hash common.Hash, config *TraceConfig) ([]*txTraceResult, error) {
	block, err := api.blockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	trace, err := api.traceBlock(ctx, block, config)
	if trace != nil && err == nil {
		return trace, nil
	}
	if api.config.ProxyOnError {
		var res []*txTraceResult
		if err := api.rpc.CallContext(ctx, &res, "debug_traceBlockByHash", hash, config); res != nil && err == nil {
			return res, nil
		}
	}
	return nil, err
}

// TraceBlock returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *TracingAPI) TraceBlock(ctx context.Context, blob hexutil.Bytes, config *TraceConfig) ([]*txTraceResult, error) {
	trace, err := api.localTraceBlock(ctx, blob, config)
	if trace != nil && err == nil {
		return trace, nil
	}
	if api.config.ProxyOnError {
		var res []*txTraceResult
		if err := api.rpc.CallContext(ctx, &res, "debug_traceBlock", blob, config); res != nil && err == nil {
			return res, nil
		}
	}
	return nil, err
}

func (api *TracingAPI) localTraceBlock(ctx context.Context, blob hexutil.Bytes, config *TraceConfig) ([]*txTraceResult, error) {
	block := new(types.Block)
	if err := rlp.Decode(bytes.NewReader(blob), block); err != nil {
		return nil, fmt.Errorf("could not decode block: %v", err)
	}
	return api.traceBlock(ctx, block, config)
}

// traceBlock configures a new tracer according to the provided configuration, and
// executes all the transactions contained within. The return value will be one item
// per transaction, dependent on the requested tracer.
func (api *TracingAPI) traceBlock(ctx context.Context, block *types.Block, config *TraceConfig) ([]*txTraceResult, error) {
	if block.NumberU64() == 0 {
		return nil, errors.New("genesis is not traceable")
	}
	stateDB, _, err := api.backend.IPLDDirectStateDBAndHeaderByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(block.ParentHash(), true))
	if err != nil {
		return nil, err
	}

	// JS tracers have high overhead. In this case run a parallel
	// process that generates states in one thread and traces txes
	// in separate worker threads.
	if config != nil && config.Tracer != nil && *config.Tracer != "" {
		if isJS := tracers.DefaultDirectory.IsJS(*config.Tracer); isJS {
			return api.traceBlockParallel(ctx, block, stateDB, config)
		}
	}
	// Native tracers have low overhead
	var (
		txs       = block.Transactions()
		blockHash = block.Hash()
		is158     = api.backend.ChainConfig().IsEIP158(block.Number())
		blockCtx  = core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
		signer    = types.MakeSigner(api.backend.ChainConfig(), block.Number())
		results   = make([]*txTraceResult, len(txs))
	)
	for i, tx := range txs {
		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		txctx := &tracers.Context{
			BlockHash:   blockHash,
			BlockNumber: block.Number(),
			TxIndex:     i,
			TxHash:      tx.Hash(),
		}
		res, err := api.traceTx(ctx, msg, txctx, blockCtx, stateDB, config)
		if err != nil {
			return nil, err
		}
		results[i] = &txTraceResult{Result: res}
		// Finalize the state so any modifications are written to the trie
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		stateDB.Finalise(is158)
	}
	return results, nil
}

// traceBlockParallel is for tracers that have a high overhead (read JS tracers). One thread
// runs along and executes txes without tracing enabled to generate their prestate.
// Worker threads take the tasks and the prestate and trace them.
func (api *TracingAPI) traceBlockParallel(ctx context.Context, block *types.Block, statedb *ipld_direct_state.StateDB, config *TraceConfig) ([]*txTraceResult, error) {
	// Execute all the transaction contained within the block concurrently
	var (
		txs       = block.Transactions()
		blockHash = block.Hash()
		blockCtx  = core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
		signer    = types.MakeSigner(api.backend.ChainConfig(), block.Number())
		results   = make([]*txTraceResult, len(txs))
		pend      sync.WaitGroup
	)
	threads := runtime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	jobs := make(chan *txTraceTask, threads)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()
			// Fetch and execute the next transaction trace tasks
			for task := range jobs {
				msg, _ := core.TransactionToMessage(txs[task.index], signer, block.BaseFee())
				txctx := &tracers.Context{
					BlockHash:   blockHash,
					BlockNumber: block.Number(),
					TxIndex:     task.index,
					TxHash:      txs[task.index].Hash(),
				}
				res, err := api.traceTx(ctx, msg, txctx, blockCtx, task.statedb, config)
				if err != nil {
					results[task.index] = &txTraceResult{Error: err.Error()}
					continue
				}
				results[task.index] = &txTraceResult{Result: res}
			}
		}()
	}

	// Feed the transactions into the tracers and return
	var failed error
txloop:
	for i, tx := range txs {
		// Send the trace task over for execution
		task := &txTraceTask{statedb: statedb.Copy(), index: i}
		select {
		case <-ctx.Done():
			failed = ctx.Err()
			break txloop
		case jobs <- task:
		}

		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, signer, block.BaseFee())
		statedb.SetTxContext(tx.Hash(), i)
		vmenv := vm.NewEVM(blockCtx, core.NewEVMTxContext(msg), statedb, api.backend.ChainConfig(), vm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.GasLimit)); err != nil {
			failed = err
			break txloop
		}
		// Finalize the state so any modifications are written to the trie
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))
	}

	close(jobs)
	pend.Wait()

	// If execution failed in between, abort
	if failed != nil {
		return nil, failed
	}
	return results, nil
}

// blockByNumberAndHash is the wrapper of the chain access function offered by
// the backend. It will return an error if the block is not found.
//
// Note this function is friendly for the light client which can only retrieve the
// historical(before the CHT) header/block by number.
func (api *TracingAPI) blockByNumberAndHash(ctx context.Context, number rpc.BlockNumber, hash common.Hash) (*types.Block, error) {
	block, err := api.blockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block.Hash() == hash {
		return block, nil
	}
	return api.blockByHash(ctx, hash)
}

type chainContext struct {
	api *TracingAPI
	ctx context.Context
}

func (context *chainContext) Engine() consensus.Engine {
	return context.api.backend.Engine()
}

func (context *chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	header, err := context.api.backend.HeaderByNumber(context.ctx, rpc.BlockNumber(number))
	if err != nil {
		return nil
	}
	if header.Hash() == hash {
		return header
	}
	header, err = context.api.backend.HeaderByHash(context.ctx, hash)
	if err != nil {
		return nil
	}
	return header
}
