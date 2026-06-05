ALTER TABLE subscriptions ADD COLUMN stripe_price_id TEXT DEFAULT '';
ALTER TABLE subscriptions ADD COLUMN billing_email TEXT DEFAULT '';
