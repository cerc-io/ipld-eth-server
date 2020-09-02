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
    state_id integer NOT NULL,
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
    id integer NOT NULL,
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
    id integer NOT NULL,
    state_id integer NOT NULL,
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
    deployment boolean NOT NULL,
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
    node_id character varying(128)
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
    ADD CONSTRAINT node_uc UNIQUE (genesis_block, network_id, node_id);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (id);


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

