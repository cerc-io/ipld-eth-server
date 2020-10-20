module github.com/vulcanize/ipld-eth-server

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.11
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/ipfs/go-block-format v0.0.2
	github.com/ipfs/go-cid v0.0.5
	github.com/ipfs/go-ipfs-blockstore v1.0.0
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.8.0
	github.com/mattn/go-sqlite3 v1.14.4 // indirect
	github.com/multiformats/go-multihash v0.0.13
	github.com/nxadm/tail v1.4.5 // indirect
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.1
	github.com/pressly/goose v2.6.0+incompatible // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	github.com/vulcanize/ipld-eth-indexer v0.5.0-alpha
	github.com/vulcanize/pg-ipfs-ethdb v0.0.1-alpha
	github.com/ziutek/mymysql v1.5.4 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/sys v0.0.0-20201018230417-eeed37f84f13 // indirect
	golang.org/x/tools v0.0.0-20201019175715-b894a3290fff // indirect
	google.golang.org/appengine v1.6.7 // indirect
)

replace github.com/ethereum/go-ethereum v1.9.11 => github.com/vulcanize/go-ethereum v1.9.11-statediff-0.0.5
