-- Extend administrator profiles and tenant registration metadata.
ALTER TABLE admins ADD COLUMN phone TEXT;
ALTER TABLE admins ADD COLUMN google_maps_url TEXT;
ALTER TABLE admins ADD COLUMN language TEXT DEFAULT 'ko';

CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);