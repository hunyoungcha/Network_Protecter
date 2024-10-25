CREATE TABLE FirewallRules (
    ip TEXT NOT NULL DEFAULT 'ANY',
    port INTEGER NOT NULL DEFAULT 'ANY',
    direction TEXT CHECK(direction IN ('IN', 'OUT')) NOT NULL DEFAULT 'IN',
    action TEXT CHECK(action IN ('PERMIT', 'DROP')) NOT NULL DEFAULT 'PERMIT'
);

INSERT INTO FirewallRules (ip, port, direction, action) VALUES
('192.168.0.1', 80, 'IN', 'PERMIT'),
('10.0.0.1', 443, 'OUT', 'PERMIT'),
('172.16.0.5', 22, 'IN', 'DROP'),
('192.168.111.1', 22, 'IN', 'PERMIT'),
('192.168.111.134', 22, 'IN','DROP');


DELETE FROM FirewallRules WHERE ip = '192.168.111.1';
-- DELETE FROM FirewallRules WHERE ip = '192.168.111.134';



-- SELECT 
--     ROW_NUMBER() OVER (ORDER BY ip) AS row_num,
--     ip, port, direction, action
-- FROM FirewallRules;

-- ROW_NUMBER() 함수를 사용하면 순서대로 자동으로 idx를 지정해줌