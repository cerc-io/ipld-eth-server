--
-- PostgreSQL database dump
--

-- Dumped from database version 12.1
-- Dumped by pg_dump version 12.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: eth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA eth;


--
-- Name: graphql_subscription(); Type: FUNCTION; Schema: eth; Owner: -
--

CREATE FUNCTION eth.graphql_subscription() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
declare
    table_name text = TG_ARGV[0];
    attribute text = TG_ARGV[1];
    id text;
begin
    execute 'select $1.' || quote_ident(attribute)
        using new
        into id;
    perform pg_notify('postgraphile:' || table_name,
                      json_build_object(
                              '__node__', json_build_array(
                              table_name,
                              id
                          )
                          )::text
        );
    return new;
end;
$_$;


--
-- Name: canonical_header(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.canonical_header(height bigint) RETURNS integer
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: header_weight(character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.header_weight(hash character varying) RETURNS bigint
    LANGUAGE sql
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
$$;


--
-- Name: was_state_removed(bytea, bigint, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.was_state_removed(path bytea, height bigint, hash character varying) RETURNS boolean
    LANGUAGE sql
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
$$;


--
-- Name: was_storage_removed(bytea, bigint, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.was_storage_removed(path bytea, height bigint, hash character varying) RETURNS boolean
    LANGUAGE sql
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
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: header_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.header_cids (
    id integer NOT NULL,
    block_number bigint NOT NULL,
    block_hash character varying(66) NOT NULL,
    parent_hash character varying(66) NOT NULL,
    cid text NOT NULL,
    mh_key text NOT NULL,
    td numeric NOT NULL,
    node_id integer NOT NULL,
    reward numeric NOT NULL,
    state_root character varying(66) NOT NULL,
    tx_root character varying(66) NOT NULL,
    receipt_root character varying(66) NOT NULL,
    uncle_root character varying(66) NOT NULL,
    bloom bytea NOT NULL,
    "timestamp" numeric NOT NULL,
    times_validated integer DEFAULT 1 NOT NULL
);


--
-- Name: TABLE header_cids; Type: COMMENT; Schema: eth; Owner: -
--

COMMENT ON TABLE eth.header_cids IS '@name EthHeaderCids';


--
-- Name: COLUMN header_cids.node_id; Type: COMMENT; Schema: eth; Owner: -
--

COMMENT ON COLUMN eth.header_cids.node_id IS '@name EthNodeID';


--
-- Name: header_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.header_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: header_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.header_cids_id_seq OWNED BY eth.header_cids.id;


--
-- Name: receipt_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.receipt_cids (
    id integer NOT NULL,
    tx_id integer NOT NULL,
    cid text NOT NULL,
    mh_key text NOT NULL,
    contract character varying(66),
    contract_hash character varying(66),
    topic0s character varying(66)[],
    topic1s character varying(66)[],
    topic2s character varying(66)[],
    topic3s character varying(66)[],
    log_contracts character varying(66)[]
);


--
-- Name: receipt_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.receipt_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: receipt_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.receipt_cids_id_seq OWNED BY eth.receipt_cids.id;


--
-- Name: state_accounts; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.state_accounts (
    id integer NOT NULL,
    state_id bigint NOT NULL,
    balance numeric NOT NULL,
    nonce integer NOT NULL,
    code_hash bytea NOT NULL,
    storage_root character varying(66) NOT NULL
);


--
-- Name: state_accounts_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.state_accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: state_accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.state_accounts_id_seq OWNED BY eth.state_accounts.id;


--
-- Name: state_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.state_cids (
    id bigint NOT NULL,
    header_id integer NOT NULL,
    state_leaf_key character varying(66),
    cid text NOT NULL,
    mh_key text NOT NULL,
    state_path bytea,
    node_type integer NOT NULL,
    diff boolean DEFAULT false NOT NULL
);


--
-- Name: state_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.state_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: state_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.state_cids_id_seq OWNED BY eth.state_cids.id;


--
-- Name: storage_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.storage_cids (
    id bigint NOT NULL,
    state_id bigint NOT NULL,
    storage_leaf_key character varying(66),
    cid text NOT NULL,
    mh_key text NOT NULL,
    storage_path bytea,
    node_type integer NOT NULL,
    diff boolean DEFAULT false NOT NULL
);


--
-- Name: storage_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.storage_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: storage_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.storage_cids_id_seq OWNED BY eth.storage_cids.id;


--
-- Name: transaction_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.transaction_cids (
    id integer NOT NULL,
    header_id integer NOT NULL,
    tx_hash character varying(66) NOT NULL,
    index integer NOT NULL,
    cid text NOT NULL,
    mh_key text NOT NULL,
    dst character varying(66) NOT NULL,
    src character varying(66) NOT NULL,
    tx_data bytea
);


--
-- Name: TABLE transaction_cids; Type: COMMENT; Schema: eth; Owner: -
--

COMMENT ON TABLE eth.transaction_cids IS '@name EthTransactionCids';


--
-- Name: transaction_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.transaction_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: transaction_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.transaction_cids_id_seq OWNED BY eth.transaction_cids.id;


--
-- Name: uncle_cids; Type: TABLE; Schema: eth; Owner: -
--

CREATE TABLE eth.uncle_cids (
    id integer NOT NULL,
    header_id integer NOT NULL,
    block_hash character varying(66) NOT NULL,
    parent_hash character varying(66) NOT NULL,
    cid text NOT NULL,
    mh_key text NOT NULL,
    reward numeric NOT NULL
);


--
-- Name: uncle_cids_id_seq; Type: SEQUENCE; Schema: eth; Owner: -
--

CREATE SEQUENCE eth.uncle_cids_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: uncle_cids_id_seq; Type: SEQUENCE OWNED BY; Schema: eth; Owner: -
--

ALTER SEQUENCE eth.uncle_cids_id_seq OWNED BY eth.uncle_cids.id;


--
-- Name: blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.blocks (
    key text NOT NULL,
    data bytea NOT NULL
);


--
-- Name: goose_db_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.goose_db_version (
    id integer NOT NULL,
    version_id bigint NOT NULL,
    is_applied boolean NOT NULL,
    tstamp timestamp without time zone DEFAULT now()
);


--
-- Name: goose_db_version_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.goose_db_version_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: goose_db_version_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.goose_db_version_id_seq OWNED BY public.goose_db_version.id;


--
-- Name: nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nodes (
    id integer NOT NULL,
    client_name character varying,
    genesis_block character varying(66),
    network_id character varying,
    node_id character varying(128),
    chain_id integer DEFAULT 1
);


--
-- Name: TABLE nodes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.nodes IS '@name NodeInfo';


--
-- Name: COLUMN nodes.node_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.nodes.node_id IS '@name ChainNodeID';


--
-- Name: nodes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nodes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nodes_id_seq OWNED BY public.nodes.id;


--
-- Name: header_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.header_cids ALTER COLUMN id SET DEFAULT nextval('eth.header_cids_id_seq'::regclass);


--
-- Name: receipt_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.receipt_cids ALTER COLUMN id SET DEFAULT nextval('eth.receipt_cids_id_seq'::regclass);


--
-- Name: state_accounts id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_accounts ALTER COLUMN id SET DEFAULT nextval('eth.state_accounts_id_seq'::regclass);


--
-- Name: state_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_cids ALTER COLUMN id SET DEFAULT nextval('eth.state_cids_id_seq'::regclass);


--
-- Name: storage_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.storage_cids ALTER COLUMN id SET DEFAULT nextval('eth.storage_cids_id_seq'::regclass);


--
-- Name: transaction_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.transaction_cids ALTER COLUMN id SET DEFAULT nextval('eth.transaction_cids_id_seq'::regclass);


--
-- Name: uncle_cids id; Type: DEFAULT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.uncle_cids ALTER COLUMN id SET DEFAULT nextval('eth.uncle_cids_id_seq'::regclass);


--
-- Name: goose_db_version id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.goose_db_version ALTER COLUMN id SET DEFAULT nextval('public.goose_db_version_id_seq'::regclass);


--
-- Name: nodes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes ALTER COLUMN id SET DEFAULT nextval('public.nodes_id_seq'::regclass);


--
-- Name: header_cids header_cids_block_number_block_hash_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.header_cids
    ADD CONSTRAINT header_cids_block_number_block_hash_key UNIQUE (block_number, block_hash);


--
-- Name: header_cids header_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.header_cids
    ADD CONSTRAINT header_cids_pkey PRIMARY KEY (id);


--
-- Name: receipt_cids receipt_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.receipt_cids
    ADD CONSTRAINT receipt_cids_pkey PRIMARY KEY (id);


--
-- Name: receipt_cids receipt_cids_tx_id_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.receipt_cids
    ADD CONSTRAINT receipt_cids_tx_id_key UNIQUE (tx_id);


--
-- Name: state_accounts state_accounts_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_accounts
    ADD CONSTRAINT state_accounts_pkey PRIMARY KEY (id);


--
-- Name: state_accounts state_accounts_state_id_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_accounts
    ADD CONSTRAINT state_accounts_state_id_key UNIQUE (state_id);


--
-- Name: state_cids state_cids_header_id_state_path_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_cids
    ADD CONSTRAINT state_cids_header_id_state_path_key UNIQUE (header_id, state_path);


--
-- Name: state_cids state_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_cids
    ADD CONSTRAINT state_cids_pkey PRIMARY KEY (id);


--
-- Name: storage_cids storage_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.storage_cids
    ADD CONSTRAINT storage_cids_pkey PRIMARY KEY (id);


--
-- Name: storage_cids storage_cids_state_id_storage_path_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.storage_cids
    ADD CONSTRAINT storage_cids_state_id_storage_path_key UNIQUE (state_id, storage_path);


--
-- Name: transaction_cids transaction_cids_header_id_tx_hash_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.transaction_cids
    ADD CONSTRAINT transaction_cids_header_id_tx_hash_key UNIQUE (header_id, tx_hash);


--
-- Name: transaction_cids transaction_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.transaction_cids
    ADD CONSTRAINT transaction_cids_pkey PRIMARY KEY (id);


--
-- Name: uncle_cids uncle_cids_header_id_block_hash_key; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.uncle_cids
    ADD CONSTRAINT uncle_cids_header_id_block_hash_key UNIQUE (header_id, block_hash);


--
-- Name: uncle_cids uncle_cids_pkey; Type: CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.uncle_cids
    ADD CONSTRAINT uncle_cids_pkey PRIMARY KEY (id);


--
-- Name: blocks blocks_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.blocks
    ADD CONSTRAINT blocks_key_key UNIQUE (key);


--
-- Name: goose_db_version goose_db_version_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.goose_db_version
    ADD CONSTRAINT goose_db_version_pkey PRIMARY KEY (id);


--
-- Name: nodes node_uc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT node_uc UNIQUE (genesis_block, network_id, node_id, chain_id);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (id);


--
-- Name: account_state_id_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX account_state_id_index ON eth.state_accounts USING btree (state_id);


--
-- Name: block_hash_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX block_hash_index ON eth.header_cids USING btree (block_hash);


--
-- Name: block_number_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX block_number_index ON eth.header_cids USING brin (block_number);


--
-- Name: header_cid_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX header_cid_index ON eth.header_cids USING btree (cid);


--
-- Name: header_mh_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX header_mh_index ON eth.header_cids USING btree (mh_key);


--
-- Name: rct_cid_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_cid_index ON eth.receipt_cids USING btree (cid);


--
-- Name: rct_contract_hash_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_contract_hash_index ON eth.receipt_cids USING btree (contract_hash);


--
-- Name: rct_contract_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_contract_index ON eth.receipt_cids USING btree (contract);


--
-- Name: rct_log_contract_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_log_contract_index ON eth.receipt_cids USING gin (log_contracts);


--
-- Name: rct_mh_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_mh_index ON eth.receipt_cids USING btree (mh_key);


--
-- Name: rct_topic0_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_topic0_index ON eth.receipt_cids USING gin (topic0s);


--
-- Name: rct_topic1_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_topic1_index ON eth.receipt_cids USING gin (topic1s);


--
-- Name: rct_topic2_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_topic2_index ON eth.receipt_cids USING gin (topic2s);


--
-- Name: rct_topic3_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_topic3_index ON eth.receipt_cids USING gin (topic3s);


--
-- Name: rct_tx_id_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX rct_tx_id_index ON eth.receipt_cids USING btree (tx_id);


--
-- Name: state_cid_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_cid_index ON eth.state_cids USING btree (cid);


--
-- Name: state_header_id_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_header_id_index ON eth.state_cids USING btree (header_id);


--
-- Name: state_leaf_key_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_leaf_key_index ON eth.state_cids USING btree (state_leaf_key);


--
-- Name: state_mh_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_mh_index ON eth.state_cids USING btree (mh_key);


--
-- Name: state_path_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_path_index ON eth.state_cids USING btree (state_path);


--
-- Name: state_root_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX state_root_index ON eth.header_cids USING btree (state_root);


--
-- Name: storage_cid_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_cid_index ON eth.storage_cids USING btree (cid);


--
-- Name: storage_leaf_key_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_leaf_key_index ON eth.storage_cids USING btree (storage_leaf_key);


--
-- Name: storage_mh_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_mh_index ON eth.storage_cids USING btree (mh_key);


--
-- Name: storage_path_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_path_index ON eth.storage_cids USING btree (storage_path);


--
-- Name: storage_root_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_root_index ON eth.state_accounts USING btree (storage_root);


--
-- Name: storage_state_id_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX storage_state_id_index ON eth.storage_cids USING btree (state_id);


--
-- Name: timestamp_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX timestamp_index ON eth.header_cids USING brin ("timestamp");


--
-- Name: tx_cid_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_cid_index ON eth.transaction_cids USING btree (cid);


--
-- Name: tx_dst_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_dst_index ON eth.transaction_cids USING btree (dst);


--
-- Name: tx_hash_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_hash_index ON eth.transaction_cids USING btree (tx_hash);


--
-- Name: tx_header_id_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_header_id_index ON eth.transaction_cids USING btree (header_id);


--
-- Name: tx_mh_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_mh_index ON eth.transaction_cids USING btree (mh_key);


--
-- Name: tx_src_index; Type: INDEX; Schema: eth; Owner: -
--

CREATE INDEX tx_src_index ON eth.transaction_cids USING btree (src);


--
-- Name: header_cids header_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER header_cids_ai AFTER INSERT ON eth.header_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('header_cids', 'id');


--
-- Name: receipt_cids receipt_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER receipt_cids_ai AFTER INSERT ON eth.receipt_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('receipt_cids', 'id');


--
-- Name: state_accounts state_accounts_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER state_accounts_ai AFTER INSERT ON eth.state_accounts FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('state_accounts', 'id');


--
-- Name: state_cids state_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER state_cids_ai AFTER INSERT ON eth.state_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('state_cids', 'id');


--
-- Name: storage_cids storage_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER storage_cids_ai AFTER INSERT ON eth.storage_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('storage_cids', 'id');


--
-- Name: transaction_cids transaction_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER transaction_cids_ai AFTER INSERT ON eth.transaction_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('transaction_cids', 'id');


--
-- Name: uncle_cids uncle_cids_ai; Type: TRIGGER; Schema: eth; Owner: -
--

CREATE TRIGGER uncle_cids_ai AFTER INSERT ON eth.uncle_cids FOR EACH ROW EXECUTE FUNCTION eth.graphql_subscription('uncle_cids', 'id');


--
-- Name: header_cids header_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.header_cids
    ADD CONSTRAINT header_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: header_cids header_cids_node_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.header_cids
    ADD CONSTRAINT header_cids_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: receipt_cids receipt_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.receipt_cids
    ADD CONSTRAINT receipt_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: receipt_cids receipt_cids_tx_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.receipt_cids
    ADD CONSTRAINT receipt_cids_tx_id_fkey FOREIGN KEY (tx_id) REFERENCES eth.transaction_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: state_accounts state_accounts_state_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_accounts
    ADD CONSTRAINT state_accounts_state_id_fkey FOREIGN KEY (state_id) REFERENCES eth.state_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: state_cids state_cids_header_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_cids
    ADD CONSTRAINT state_cids_header_id_fkey FOREIGN KEY (header_id) REFERENCES eth.header_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: state_cids state_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.state_cids
    ADD CONSTRAINT state_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: storage_cids storage_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.storage_cids
    ADD CONSTRAINT storage_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: storage_cids storage_cids_state_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.storage_cids
    ADD CONSTRAINT storage_cids_state_id_fkey FOREIGN KEY (state_id) REFERENCES eth.state_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: transaction_cids transaction_cids_header_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.transaction_cids
    ADD CONSTRAINT transaction_cids_header_id_fkey FOREIGN KEY (header_id) REFERENCES eth.header_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: transaction_cids transaction_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.transaction_cids
    ADD CONSTRAINT transaction_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: uncle_cids uncle_cids_header_id_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.uncle_cids
    ADD CONSTRAINT uncle_cids_header_id_fkey FOREIGN KEY (header_id) REFERENCES eth.header_cids(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: uncle_cids uncle_cids_mh_key_fkey; Type: FK CONSTRAINT; Schema: eth; Owner: -
--

ALTER TABLE ONLY eth.uncle_cids
    ADD CONSTRAINT uncle_cids_mh_key_fkey FOREIGN KEY (mh_key) REFERENCES public.blocks(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- PostgreSQL database dump complete
--

