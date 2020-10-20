-- +goose Up
ALTER TABLE public.nodes
ADD COLUMN chain_id INTEGER DEFAULT 1;

ALTER TABLE public.nodes
DROP CONSTRAINT node_uc;

ALTER TABLE public.nodes
ADD CONSTRAINT node_uc
UNIQUE (genesis_block, network_id, node_id, chain_id);

-- +goose Down
ALTER TABLE public.nodes
DROP CONSTRAINT node_uc;

ALTER TABLE public.nodes
ADD CONSTRAINT node_uc
UNIQUE (genesis_block, network_id, node_id);

ALTER TABLE public.nodes
DROP COLUMN chain_id;