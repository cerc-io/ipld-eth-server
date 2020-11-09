-- +goose Up
ALTER FUNCTION canonical_header RENAME TO canonical_header_id;

-- +goose StatementBegin
CREATE TYPE child_result AS (
  has_child BOOLEAN,
  children eth.header_cids[]
);

CREATE OR REPLACE FUNCTION has_child(hash VARCHAR(66)) RETURNS child_result AS
$BODY$
DECLARE
  new_child_result child_result;
BEGIN
  -- short circuit if there are no children
  SELECT exists(SELECT 1
                FROM eth.header_cids
                WHERE parent_hash = hash
                LIMIT 1)
  INTO new_child_result.has_child;
  -- collect all the children for this header
  IF new_child_result.has_child THEN
    SELECT *
    INTO new_child_result.children
    FROM eth.header_cids
    WHERE parent_hash = hash;
  ELSE
  END IF;
  RETURN new_child_result;
END
$BODY$
LANGUAGE 'plpgsql';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION canonical_header_from_set(headers eth.header_cids[]) RETURNS eth.header_cids AS
$BODY$
DECLARE
  canonical_header eth.header_cids;
  canonical_child eth.header_cids;
  header eth.header_cids;
  current_child_result child_result;
  child_headers eth.header_cids[];
  current_header_with_child eth.header_cids;
  has_children_count INT DEFAULT 0;
BEGIN
  -- for each header in the provided set
  FOR header IN SELECT * FROM headers
  LOOP
    -- check if it has any children
    SELECT * INTO current_child_result FROM has_child(header.block_hash);
    IF current_child_result.has_child THEN
      -- if it does, take note
      has_children_count = has_children_count + 1;
      current_header_with_child = header;
      -- and add the children to the growing set of child headers
      child_headers = array_cat(child_headers, current_child_result.children);
    END IF;
  END LOOP;
  -- if none of the headers had children, none is more canonical than the other
  IF has_children_count = 0 THEN
    -- return the first one selected
    SELECT * INTO canonical_header FROM headers LIMIT 1;
  -- if only one header had children, it can be considered the heaviest/canonical header of the set
  ELSIF has_children_count = 1 THEN
    -- return the only header with a child
    canonical_header = current_header_with_child;
  -- if there are multiple headers with children
  ELSE
    -- find the canonical the canonical header from the child set
    canonical_child = canonical_header_from_set(child_headers);
    -- the header that is parent to this header, is the canonical header at this level
    SELECT * INTO canonical_header FROM headers
    WHERE block_hash = canonical_child.parent_hash;
  END IF;
  RETURN canonical_header;
END
$BODY$
LANGUAGE 'plpgsql';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION canonical_header(height BIGINT) RETURNS eth.header_cids AS
$BODY$
DECLARE
  header_count INT;
  headers eth.header_cids[];
BEGIN
  -- collect every header at this height, noting how many are collected
  SELECT *, count(*)
  INTO headers, header_count
  FROM eth.header_cids
  WHERE block_number = height;
  -- if only one header is present, it can be considered canonical (if no header is present we will throw an error)
  IF header_count = 1 THEN
    RETURN headers[0];
  END IF;
  -- otherwise, if there are multiple headers at this height, we need to determine which is canonical
  RETURN canonical_header_from_set(headers);
END
$BODY$
LANGUAGE 'plpgsql';
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION canonical_header;
DROP FUNCTION canonical_header_from_set;
DROP FUNCTION has_child;
DROP TYPE child_result;
ALTER FUNCTION canonical_header_id RENAME TO canonical_header;
