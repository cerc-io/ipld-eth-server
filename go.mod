module github.com/vulcanize/ipld-eth-server

go 1.15

require (
	github.com/ethereum/go-ethereum v1.10.16
	github.com/graph-gophers/graphql-go v1.3.0
	github.com/ipfs/go-block-format v0.0.3
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipfs-blockstore v1.0.1
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.3.5
	github.com/joho/godotenv v1.4.0
	github.com/lib/pq v1.10.5
	github.com/machinebox/graphql v0.2.2
	github.com/mailgun/groupcache/v2 v2.3.0
	github.com/matryer/is v1.4.0 // indirect
	github.com/multiformats/go-multihash v0.0.15
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.19.0
	github.com/prometheus/client_golang v1.11.0
	github.com/shirou/gopsutil v3.21.5+incompatible // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.11.0
	github.com/tklauser/go-sysconf v0.3.6 // indirect
	github.com/vulcanize/eth-ipfs-state-validator v0.1.0
	github.com/vulcanize/gap-filler v0.3.1
	github.com/vulcanize/ipfs-ethdb v0.0.6
	golang.org/x/tools v0.1.8 // indirect
)

replace (
	github.com/ethereum/go-ethereum v1.10.16 => github.com/deep-stack/go-ethereum v1.10.16-statediff-3.0.2.0.20220506051110-2ef7dfe9bea8
	github.com/vulcanize/eth-ipfs-state-validator v0.1.0 => github.com/deep-stack/eth-ipfs-state-validator v0.3.1-0.20220503143856-da09507c389e
	github.com/vulcanize/ipfs-ethdb v0.0.6 => github.com/deep-stack/ipfs-ethdb v0.0.7-0.20220503143614-9074389df276
)
