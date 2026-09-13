-- Run this once in the NEW database's console (lesson-scheduler-db → Console).
-- This is everything needed from scratch — the studio data table plus accounts.

CREATE TABLE IF NOT EXISTS app_state (
  id INTEGER PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS teachers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  instrument TEXT,
  slug TEXT UNIQUE,
  onboarded INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS login_tokens (
  token TEXT PRIMARY KEY,
  teacher_id INTEGER NOT NULL REFERENCES teachers(id),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- No insert needed here, unlike your personal project — this database
-- starts genuinely empty, so logging in for the first time and going
-- through onboarding for real is exactly the right way to test it.
