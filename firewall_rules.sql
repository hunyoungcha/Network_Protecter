-- SQLite
-- CREATE TABLE FirewallRules (
--     num INTEGER PRIMARY KEY AUTOINCREMENT, 
--     ip TEXT NOT NULL DEFAULT 'ANY',                      
--     port INTEGER NOT NULL DEFAULT 'ANY',                 
--     direction TEXT CHECK(direction IN ('IN', 'OUT')) NOT NULL 
-- );

-- INSERT INTO FirewallRules (ip, port, direction) VALUES
-- ('192.168.0.1', 80, 'IN'),
-- ('10.0.0.1', 443, 'OUT'),
-- ('172.16.0.5', 22, 'IN'),

-- ALTER TABLE FirewallRules 
-- ADD COLUMN action TEXT CHECK(action IN ('PERMIT', 'DROP')) NOT NULL DEFAULT 'DROP';

CREATE TABLE FirewallRules_new (
    num INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL DEFAULT 'ANY',
    port INTEGER NOT NULL DEFAULT 'ANY',
    direction TEXT CHECK(direction IN ('IN', 'OUT')) NOT NULL,
    action TEXT CHECK(action IN ('PERMIT', 'DROP')) NOT NULL DEFAULT 'PERMIT'
);

INSERT INTO FirewallRules_new (num, ip, port, direction, action)
SELECT num, ip, port, direction, 'PERMIT' FROM FirewallRules;

DROP TABLE FirewallRules;

ALTER TABLE FirewallRules_new RENAME TO FirewallRules;
