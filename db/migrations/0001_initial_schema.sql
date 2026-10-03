-- Massage SaaS D1 initial schema
-- Version: DB-v1
-- Design: one D1 database, isolated by shop_id (tenant)
-- Existing localStorage data is intentionally NOT modified by this migration.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS shops (
  id TEXT PRIMARY KEY,
  shop_name TEXT NOT NULL,
  email TEXT,
  address TEXT,
  google_maps_url TEXT,
  currency_code TEXT DEFAULT 'THB',
  currency_name TEXT DEFAULT 'Baht',
  currency_symbol TEXT DEFAULT '฿',
  valid_until TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  role TEXT NOT NULL DEFAULT 'manager',
  email TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  valid_until TEXT,
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE RESTRICT,
  UNIQUE (shop_id, username)
);

CREATE TABLE IF NOT EXISTS shop_settings (
  shop_id TEXT PRIMARY KEY,
  settings_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  name TEXT NOT NULL,
  sequence_no INTEGER,
  status TEXT NOT NULL DEFAULT 'active',
  bank_name TEXT,
  bank_account TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_staff_shop_sequence ON staff(shop_id, sequence_no);
CREATE INDEX IF NOT EXISTS idx_staff_shop_name ON staff(shop_id, name);

CREATE TABLE IF NOT EXISTS menus (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  menu_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  display_order INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS menu_prices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  menu_id INTEGER NOT NULL,
  duration_minutes INTEGER NOT NULL,
  price REAL NOT NULL DEFAULT 0,
  commission_value REAL NOT NULL DEFAULT 0,
  commission_type TEXT NOT NULL DEFAULT 'amount',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (menu_id) REFERENCES menus(id) ON DELETE CASCADE,
  UNIQUE (menu_id, duration_minutes)
);

CREATE INDEX IF NOT EXISTS idx_menu_prices_menu ON menu_prices(menu_id);

CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  room_number TEXT NOT NULL,
  capacity INTEGER DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  display_order INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  UNIQUE (shop_id, room_number)
);

CREATE TABLE IF NOT EXISTS payment_methods (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  display_order INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  UNIQUE (shop_id, name)
);

CREATE TABLE IF NOT EXISTS reservations (
  id TEXT PRIMARY KEY,
  shop_id TEXT NOT NULL,
  reservation_date TEXT NOT NULL,
  staff_id INTEGER,
  room_id INTEGER,
  customer_name TEXT,
  start_time TEXT,
  duration_minutes INTEGER,
  menu_order INTEGER DEFAULT 0,
  price REAL NOT NULL DEFAULT 0,
  commission_value REAL NOT NULL DEFAULT 0,
  commission_type TEXT NOT NULL DEFAULT 'amount',
  payment_status TEXT NOT NULL DEFAULT 'unpaid',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE SET NULL,
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_reservations_shop_date ON reservations(shop_id, reservation_date);
CREATE INDEX IF NOT EXISTS idx_reservations_shop_staff_date ON reservations(shop_id, staff_id, reservation_date);
CREATE INDEX IF NOT EXISTS idx_reservations_shop_room_date ON reservations(shop_id, room_id, reservation_date);
CREATE INDEX IF NOT EXISTS idx_reservations_payment_status ON reservations(shop_id, payment_status);

CREATE TABLE IF NOT EXISTS reservation_menus (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reservation_id TEXT NOT NULL,
  menu_id INTEGER,
  menu_name_snapshot TEXT,
  duration_minutes INTEGER,
  price REAL NOT NULL DEFAULT 0,
  commission_value REAL NOT NULL DEFAULT 0,
  commission_type TEXT NOT NULL DEFAULT 'amount',
  menu_order INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (reservation_id) REFERENCES reservations(id) ON DELETE CASCADE,
  FOREIGN KEY (menu_id) REFERENCES menus(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_reservation_menus_reservation ON reservation_menus(reservation_id);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  payment_method_id INTEGER,
  payment_method_name_snapshot TEXT,
  amount REAL NOT NULL DEFAULT 0,
  paid_at TEXT,
  status TEXT NOT NULL DEFAULT 'completed',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  FOREIGN KEY (reservation_id) REFERENCES reservations(id) ON DELETE CASCADE,
  FOREIGN KEY (payment_method_id) REFERENCES payment_methods(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_payments_shop_date ON payments(shop_id, paid_at);
CREATE INDEX IF NOT EXISTS idx_payments_reservation ON payments(reservation_id);

CREATE TABLE IF NOT EXISTS guarantees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  staff_id INTEGER,
  guarantee_date TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  commission_value REAL NOT NULL DEFAULT 0,
  commission_type TEXT NOT NULL DEFAULT 'amount',
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_guarantees_shop_date ON guarantees(shop_id, guarantee_date);
CREATE INDEX IF NOT EXISTS idx_guarantees_shop_staff_date ON guarantees(shop_id, staff_id, guarantee_date);

CREATE TABLE IF NOT EXISTS excel_imports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT NOT NULL,
  imported_by_admin_id INTEGER,
  file_name TEXT,
  row_count INTEGER DEFAULT 0,
  imported_count INTEGER DEFAULT 0,
  failed_count INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'completed',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE,
  FOREIGN KEY (imported_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id TEXT,
  admin_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE SET NULL,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_shop_created ON audit_logs(shop_id, created_at);

-- Helpful integrity indexes for tenant isolation.
CREATE INDEX IF NOT EXISTS idx_admins_shop ON admins(shop_id);
CREATE INDEX IF NOT EXISTS idx_menus_shop ON menus(shop_id);
CREATE INDEX IF NOT EXISTS idx_rooms_shop ON rooms(shop_id);
CREATE INDEX IF NOT EXISTS idx_payment_methods_shop ON payment_methods(shop_id);
