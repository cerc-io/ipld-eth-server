-- +goose Up
ALTER TABLE eth.receipt_cids
ADD COLUMN post_state VARCHAR(66);

ALTER TABLE eth.receipt_cids
ADD COLUMN post_status INTEGER;

-- +goose Down
ALTER TABLE eth.receipt_cids
DROP COLUMN post_status;

ALTER TABLE eth.receipt_cids
DROP COLUMN post_state;