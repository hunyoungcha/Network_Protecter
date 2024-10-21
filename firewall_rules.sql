CREATE TABLE FirewallRules (
    ip TEXT NOT NULL DEFAULT 'ANY',
    port INTEGER NOT NULL DEFAULT 'ANY',
    direction TEXT CHECK(direction IN ('IN', 'OUT')) NOT NULL,
    action TEXT CHECK(action IN ('PERMIT', 'DROP')) NOT NULL DEFAULT 'PERMIT'
);

INSERT INTO FirewallRules (ip, port, direction, action) VALUES
('192.168.0.1', 80, 'IN', 'PERMIT'),
('10.0.0.1', 443, 'OUT', 'PERMIT'),
('172.16.0.5', 22, 'IN', 'DROP');

-- SELECT 
--     ROW_NUMBER() OVER (ORDER BY ip) AS row_num,
--     ip, port, direction, action
-- FROM FirewallRules;

-- SELECT 할 때 ROW_NUMBER() 함수를 사용하면 순서대로 자동으로 idx를 지정해줌