-- +goose Up
ALTER TABLE eth.receipt_cids
ADD COLUMN log_contracts VARCHAR(66)[];

ALTER TABLE eth.receipt_cids
RENAME COLUMN contract TO contract_hash;

WITH uniques AS (SELECT DISTINCT ON (tx_id) * FROM eth.receipt_cids)
DELETE FROM eth.receipt_cids WHERE receipt_cids.id NOT IN (SELECT id FROM uniques);

ALTER TABLE eth.receipt_cids
ADD CONSTRAINT receipt_cids_tx_id_key UNIQUE (tx_id);

-- +goose Down
ALTER TABLE eth.receipt_cids
DROP CONSTRAINT receipt_cids_tx_id_key;

ALTER TABLE eth.receipt_cids
RENAME COLUMN contract_hash TO contract;

ALTER TABLE eth.receipt_cids
DROP COLUMN log_contracts;