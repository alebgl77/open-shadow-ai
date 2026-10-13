ALTER TABLE shadai.events ADD COLUMN IF NOT EXISTS extension_version String DEFAULT '';
ALTER TABLE shadai.events ADD COLUMN IF NOT EXISTS extension_enabled Nullable(UInt8);
ALTER TABLE shadai.events ADD COLUMN IF NOT EXISTS extension_install_source LowCardinality(String) DEFAULT '';
ALTER TABLE shadai.events ADD COLUMN IF NOT EXISTS extension_installed_at Nullable(DateTime64(3, 'UTC'));
ALTER TABLE shadai.events ADD COLUMN IF NOT EXISTS browser_profile String DEFAULT '';
