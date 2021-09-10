-- +goose Up
CREATE TABLE eth.access_list_element (
   id                    SERIAL PRIMARY KEY,
   tx_id                 INTEGER NOT NULL REFERENCES eth.transaction_cids (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
   index                 INTEGER NOT NULL,
   address               VARCHAR(66),
   storage_keys          VARCHAR(66)[],
   UNIQUE (tx_id, index)
);

CREATE INDEX accesss_list_element_address_index ON eth.access_list_element USING btree (address);

-- +goose Down
DROP INDEX eth.accesss_list_element_address_index;
DROP TABLE eth.access_list_element;
