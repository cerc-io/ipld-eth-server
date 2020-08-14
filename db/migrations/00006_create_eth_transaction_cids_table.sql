-- +goose Up
CREATE TABLE eth.transaction_cids (
  id                    SERIAL PRIMARY KEY,
  header_id             INTEGER NOT NULL REFERENCES eth.header_cids (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  tx_hash               VARCHAR(66) NOT NULL,
  index                 INTEGER NOT NULL,
  cid                   TEXT NOT NULL,
  mh_key                TEXT NOT NULL REFERENCES public.blocks (key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  dst                   VARCHAR(66) NOT NULL,
  src                   VARCHAR(66) NOT NULL,
  deployment            BOOL NOT NULL,
  tx_data               BYTEA,
  UNIQUE (header_id, tx_hash)
);

-- +goose Down
DROP TABLE eth.transaction_cids;
