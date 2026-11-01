-- A second database for the tests, so a test never touches daas_auth.
-- Same two accounts, same rights as on daas_auth.
CREATE DATABASE daas_auth_test CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES
  ON daas_auth_test.* TO 'daas_migrate'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON daas_auth_test.* TO 'daas_app'@'%';
