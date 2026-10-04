-- Persist the existing browser/localStorage application data in D1.
-- One row per shop + logical localStorage key keeps the current UI code compatible
-- while making the server the source of truth across devices.
CREATE TABLE IF NOT EXISTS app_data (
  shop_id TEXT NOT NULL,
  data_key TEXT NOT NULL,
  data_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (shop_id, data_key),
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_data_shop_id ON app_data(shop_id);
