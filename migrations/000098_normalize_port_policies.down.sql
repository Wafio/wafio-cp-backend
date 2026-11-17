-- 000098_normalize_port_policies (DOWN)
-- Irreversible data normalisation: the original spellings of the port rules
-- are not kept, so there is nothing to restore. Most rewrites keep what the
-- dataplane enforced before (unknown action → drop, unknown proto → any,
-- unknown direction → ingress; removed port-0 rules never matched), but a
-- differently-cased known action changed meaning: "Allow" was enforced as
-- DROP and is now allow, as written. Rolling back the schema version does
-- not bring the DROP back. The statement keeps the file non-empty.
SELECT 1;
