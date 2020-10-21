-- +goose Up
ALTER TABLE eth.transaction_cids
DROP COLUMN deployment;

-- +goose Down
ALTER TABLE eth.transaction_cids
ADD COLUMN deployment BOOL NOT NULL DEFAULT FALSE;