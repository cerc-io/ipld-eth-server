-- +goose Up
-- +goose StatementBegin
-- returns the number of child headers that reference backwards to the header with the provided hash
CREATE OR REPLACE FUNCTION header_weight(hash VARCHAR(66)) RETURNS BIGINT
AS $$
  WITH RECURSIVE validator AS (
          SELECT block_hash, parent_hash, block_number
          FROM eth.header_cids
          WHERE block_hash = hash
      UNION
          SELECT eth.header_cids.block_hash, eth.header_cids.parent_hash, eth.header_cids.block_number
          FROM eth.header_cids
          INNER JOIN validator
            ON eth.header_cids.parent_hash = validator.block_hash
            AND eth.header_cids.block_number = validator.block_number + 1
  )
  SELECT COUNT(*) FROM validator;
$$ LANGUAGE SQL;
-- +goose StatementEnd

-- +goose StatementBegin
-- returns the id for the header at the provided height which is heaviest
CREATE OR REPLACE FUNCTION canonical_header(height BIGINT) RETURNS INT AS
$BODY$
DECLARE
  current_weight INT;
  heaviest_weight INT DEFAULT 0;
  heaviest_id INT;
  r eth.header_cids%ROWTYPE;
BEGIN
  FOR r IN SELECT * FROM eth.header_cids
  WHERE block_number = height
  LOOP
    SELECT INTO current_weight * FROM header_weight(r.block_hash);
    IF current_weight > heaviest_weight THEN
        heaviest_weight := current_weight;
        heaviest_id := r.id;
    END IF;
  END LOOP;
  RETURN heaviest_id;
END
$BODY$
LANGUAGE 'plpgsql';
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION header_weight;
DROP FUNCTION canonical_header;