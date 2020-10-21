-- +goose Up
ALTER TABLE eth.storage_cids
ALTER COLUMN state_id TYPE BIGINT;

ALTER TABLE eth.state_accounts
ALTER COLUMN state_id TYPE BIGINT;

ALTER TABLE eth.state_cids
ALTER COLUMN id TYPE BIGINT;

ALTER TABLE eth.storage_cids
ALTER COLUMN id TYPE BIGINT;

-- +goose Down
ALTER TABLE eth.storage_cids
ALTER COLUMN id TYPE INTEGER;

ALTER TABLE eth.state_cids
ALTER COLUMN id TYPE INTEGER;

ALTER TABLE eth.state_accounts
ALTER COLUMN state_id TYPE INTEGER;

ALTER TABLE eth.storage_cids
ALTER COLUMN state_id TYPE INTEGER;