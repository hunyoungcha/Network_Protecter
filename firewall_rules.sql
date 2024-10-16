-- SQLite
CREATE TABLE FirewallRules (
    num INTEGER PRIMARY KEY AUTOINCREMENT, 
    ip TEXT NOT NULL,                      
    port INTEGER NOT NULL,                 
    direction TEXT CHECK(direction IN ('IN', 'OUT')) NOT NULL 
);

INSERT INTO FirewallRules (ip, port, direction) VALUES
('192.168.0.1', 80, 'IN'),
('10.0.0.1', 443, 'OUT'),
('172.16.0.5', 22, 'IN');