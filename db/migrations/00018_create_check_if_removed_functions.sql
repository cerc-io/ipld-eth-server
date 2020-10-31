-- +goose Up
-- +goose StatementBegin
-- returns if a storage node at the provided path was removed in the range > the provided height and <= the provided block hash
CREATE OR REPLACE FUNCTION was_storage_removed(path BYTEA, height BIGINT, hash VARCHAR(66)) RETURNS BOOLEAN
AS $$
  SELECT exists(SELECT *
					FROM eth.storage_cids
            INNER JOIN eth.state_cids ON (storage_cids.state_id = state_cids.id)
            INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
					WHERE storage_path = path
					AND block_number > height
					AND block_number <= (SELECT block_number
										FROM eth.header_cids
										WHERE block_hash = hash)
					AND storage_cids.node_type = 3);
$$ LANGUAGE SQL;
-- +goose StatementEnd

-- +goose StatementBegin
-- returns if a state node at the provided path was removed in the range > the provided height and <= the provided block hash
CREATE OR REPLACE FUNCTION was_state_removed(path BYTEA, height BIGINT, hash VARCHAR(66)) RETURNS BOOLEAN
AS $$
  SELECT exists(SELECT *
					FROM eth.state_cids
            INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
					WHERE state_path = path
					AND block_number > height
					AND block_number <= (SELECT block_number
										FROM eth.header_cids
										WHERE block_hash = hash)
					AND state_cids.node_type = 3);
$$ LANGUAGE SQL;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION was_storage_removed;
DROP FUNCTION was_state_removed;