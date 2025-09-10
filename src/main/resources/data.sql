--H2 DB SQLs

--CREATE TABLE IF NOT EXISTS users (
--    username VARCHAR(50) NOT NULL PRIMARY KEY,
--    password VARCHAR(100) NOT NULL,
--    enabled BOOLEAN NOT NULL
--);
--
--CREATE TABLE IF NOT EXISTS authorities (
--    username VARCHAR(50) NOT NULL,
--    authority VARCHAR(50) NOT NULL,
--    FOREIGN KEY (username) REFERENCES users(username),
--    UNIQUE (username, authority)
--);

--POSTGRESQL DB SQLs
DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled boolean NOT NULL
);

-- Create authorities table
CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users foreign key(username) references users(username)
);

CREATE UNIQUE index ix_auth_username on authorities(username, authority)