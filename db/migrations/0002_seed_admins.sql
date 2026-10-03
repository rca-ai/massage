-- Massage SaaS D1 seed data
-- Version: DB-v2
-- Seeds the existing development accounts so login can move to D1.
-- Passwords are stored as salt:SHA-256(salt + password).

INSERT OR IGNORE INTO shops (
  id, shop_name, address, status, created_at, updated_at
) VALUES
  ('system', 'Admin Menu', '', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('shop-rca', 'RCA Massage', '', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
  ('shop-test', '테스트 마사지', '', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT OR IGNORE INTO admins (
  shop_id, username, password_hash, display_name, role, status, valid_until
) VALUES
  ('system', 'admin',
   'd17aa9696bab05ead7ba7e4517acbd2e:cc0ed747743acc9cb218def8430fb9d4e6cf15d4d78dadd3ee754ee48f76715c',
   '최고 관리자', 'super', 'active', NULL),
  ('shop-rca', 'rca',
   'ebfea6171edec56da584c8f1aa36fc9b:2c83beb5338eba41d3b6f008378d6707f6fdf0961ebb11b1e7bbc1354ea0844f',
   'RCA Massage', 'manager', 'active', date('now', '+1 year')),
  ('shop-test', 'Test',
   'bfaacfa0b8b904975f3ab75ea3629b2c:26fbbf3ee40c0dded5698b06ef5cfa94ff4b62f4507c2a5006eff931c120be97',
   '테스트 마사지', 'manager', 'active', date('now', '+1 year'));
