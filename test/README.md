# Test Insructions

## Setup

- Clone [stack-orchestrator](https://github.com/vulcanize/stack-orchestrator) and [go-ethereum](https://github.com/vulcanize/go-ethereum) repositories.

- Checkout [v4 release](https://github.com/vulcanize/go-ethereum/releases/tag/v1.10.17-statediff-4.0.1-alpha) in go-ethereum repo.
  ```bash
  # In go-ethereum repo.
  git checkout v1.10.17-statediff-4.0.1-alpha
  ```

- Checkout working commit in stack-orchestrator repo.
  ```bash
  # In stack-orchestrator repo.
  git checkout 35c677433aee5fafdf74eb3c251a453691b818d0
  ```

## Run

- Run unit tests:

  ```bash
  # In ipld-eth-server root directory.
  ./scripts/run_unit_test.sh
  ```

- Run integration tests:

  - In stack-orchestrator repo, create config file:

    ```bash
    cd helper-scripts

    ./create-config.sh
    ```

    A `config.sh` will be created in the root directory.

  - Update/Edit the generated config file with:

    ```bash
    #!/bin/bash

    # Path to go-ethereum repo.
    vulcanize_go_ethereum=~/go-ethereum/

    # Path to ipld-eth-server repo.
    vulcanize_ipld_eth_server=~/ipld-eth-server/

    # Path to test contract.
    vulcanize_test_contract=~/ipld-eth-server/test/contract

    db_write=true
    eth_forward_eth_calls=false
    eth_proxy_on_error=false
    eth_http_path="go-ethereum:8545"
      ```

  - Run stack-orchestrator:

    ```bash
    # In stack-orchestrator root directory.
    cd helper-scripts

    ./wrapper.sh \
    -e docker \
    -d ../docker/latest/docker-compose-db.yml \
    -d ../docker/local/docker-compose-go-ethereum.yml \
    -d ../docker/local/docker-compose-ipld-eth-server.yml \
    -d ../docker/local/docker-compose-contract.yml \
    -v remove \
    -p ../config.sh
    ```

  - Run test:

    ```bash
    # In ipld-eth-server root directory.
    ./scripts/run_integration_test.sh
    ```

  - Update stack-orchestrator `config.sh` file:

    ```bash
    #!/bin/bash

    # Path to go-ethereum repo.
    vulcanize_go_ethereum=~/go-ethereum/

    # Path to ipld-eth-server repo.
    vulcanize_ipld_eth_server=~/ipld-eth-server/

    # Path to test contract.
    vulcanize_test_contract=~/ipld-eth-server/test/contract

    db_write=false
    eth_forward_eth_calls=true
    eth_proxy_on_error=false
    eth_http_path="go-ethereum:8545"
    ```

  - Stop the stack-orchestrator and start again using the same command

  - Run integration tests for direct proxy fall-through of eth_calls:
    ```bash
    ./scripts/run_integration_test_forward_eth_calls.sh
    ```
