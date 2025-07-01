-- Drop auth_users table as part of auth service refactor
-- User data is now stored only in User Service
DROP TABLE IF EXISTS auth_users; 