/* contrib/pgnodemx/pgnodemx--1.1--1.2.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgnodemx" to load this file. \quit

CREATE FUNCTION set_subtree(TEXT)
RETURNS TEXT
AS 'MODULE_PATHNAME', 'pgnodemx_set_subtree'
LANGUAGE C STABLE STRICT;
REVOKE EXECUTE ON FUNCTION set_subtree(TEXT) FROM PUBLIC;

CREATE FUNCTION set_one_control(TEXT, TEXT)
RETURNS TEXT
AS 'MODULE_PATHNAME', 'pgnodemx_set_one_control'
LANGUAGE C STABLE STRICT;
REVOKE EXECUTE ON FUNCTION set_one_control(TEXT, TEXT) FROM PUBLIC;
