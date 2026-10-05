-- A separate, disposable database for the test suite (development only).
-- Tests DROP and TRUNCATE tables, so they must never touch the real "auth" database.
-- The test fixtures refuse any database whose name doesn't end in _test.
CREATE DATABASE auth_test;
