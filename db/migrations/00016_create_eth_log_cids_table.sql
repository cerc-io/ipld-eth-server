-- +goose Up
CREATE TABLE eth.log_cids (
    id                    SERIAL PRIMARY KEY,
    receipt_id            INTEGER NOT NULL REFERENCES eth.receipt_cids (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    address               TEXT NOT NULL,
    cid                   TEXT NOT NULL,
    mh_key                TEXT NOT NULL REFERENCES public.blocks (key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    block_number          BIGINT NOT NULL,
    block_hash            VARCHAR(66) NOT NULL,
    tx_hash               VARCHAR(66) NOT NULL,
    tx_index              INTEGER NOT NULL,
    index                 INTEGER NOT NULL,
    topic0s               VARCHAR(66)[],
    topic1s               VARCHAR(66)[],
    topic2s               VARCHAR(66)[],
    topic3s               VARCHAR(66)[],
    UNIQUE (block_hash, tx_hash, index)
);

-- TODO: Remove topics from receipts to avoid redundancy.
-- ALTER TABLE eth.receipt_cids
-- DROP COLUMN topic0s,
-- DROP COLUMN topic1s,
-- DROP COLUMN topic2s,
-- DROP COLUMN topic3s,
ALTER TABLE eth.receipt_cids
ADD  COLUMN log_root VARCHAR(66);

CREATE INDEX log_rct_id_index ON eth.log_cids USING btree (receipt_id);

CREATE INDEX log_mh_index ON eth.log_cids USING btree (mh_key);

CREATE INDEX log_cid_index ON eth.log_cids USING btree (cid);

--
-- Name: log_topic0_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX log_topic0_index ON eth.log_cids USING gin (topic0s);


--
-- Name: log_topic1_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX log_topic1_index ON eth.log_cids USING gin (topic1s);


--
-- Name: log_topic2_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX log_topic2_index ON eth.log_cids USING gin (topic2s);


--
-- Name: log_topic3_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX log_topic3_index ON eth.log_cids USING gin (topic3s);


-- +goose Down
DROP TABLE eth.logs;