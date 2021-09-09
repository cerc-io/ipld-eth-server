-- +goose Up
CREATE TABLE eth.header_cids (
  id                    SERIAL PRIMARY KEY,
  block_number          BIGINT NOT NULL,
  block_hash            VARCHAR(66) NOT NULL,
  parent_hash           VARCHAR(66) NOT NULL,
  cid                   TEXT NOT NULL,
  mh_key                TEXT NOT NULL REFERENCES public.blocks (key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  td                    NUMERIC NOT NULL,
  node_id               INTEGER NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  reward                NUMERIC NOT NULL,
  state_root            VARCHAR(66) NOT NULL,
  tx_root               VARCHAR(66) NOT NULL,
  receipt_root          VARCHAR(66) NOT NULL,
  uncle_root            VARCHAR(66) NOT NULL,
  bloom                 BYTEA NOT NULL,
  timestamp             NUMERIC NOT NULL,
  times_validated       INTEGER NOT NULL DEFAULT 1,
  base_fee              BIGINT,
  UNIQUE (block_number, block_hash)
);

CREATE FUNCTION "ethHeaderCidByBlockNumber"(n bigint) returns SETOF eth.header_cids
    stable
    language sql
as
$$
SELECT * FROM eth.header_cids WHERE block_number=$1 ORDER BY id
    $$;

-- +goose Down
DROP FUNCTION "ethHeaderCidByBlockNumber"(bigint);
DROP TABLE eth.header_cids;