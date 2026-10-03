-- DB-v6.1: preserve local staff IDs for staged migration

ALTER TABLE staff ADD COLUMN legacy_id INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_shop_legacy_id
  ON staff(shop_id, legacy_id);
