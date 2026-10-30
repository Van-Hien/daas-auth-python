# Runs once, when the data volume is still empty. Creates the two accounts.
# daas_migrate: changes the schema (Alembic). 
# daas_app: only reads and writes data.
# Neither gets DELETE HISTORY, so the history of the temporal tables can't be wiped.
docker_process_sql <<EOSQL
    CREATE USER 'daas_migrate'@'%' IDENTIFIED BY '${DAAS_DB_MIGRATE_PASSWORD}';
    GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES
      ON daas_auth.* TO 'daas_migrate'@'%';
    CREATE USER 'daas_app'@'%' IDENTIFIED BY '${DAAS_DB_APP_PASSWORD}';
    GRANT SELECT, INSERT, UPDATE, DELETE ON daas_auth.* TO 'daas_app'@'%';
EOSQL