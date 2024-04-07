#!/bin/bash

# Define the backup directory name with timestamp
BACKUP_DIR="backup"

# Create the backup directory
mkdir -p "$BACKUP_DIR"

# Define the archive file name
ARCHIVE_NAME="log_and_config_backup_$(date +%Y%m%d_%H%M%S).tar.gz"

# Check and copy nginx logs if they exist
if [ -d "/var/log/nginx" ]; then
  cp -r /var/log/nginx "$BACKUP_DIR/"
fi

if [ -d "/etc/modsecurity/" ]; then
  cp -r /etc/modsecurity "$BACKUP_DIR/"
fi

# Check and copy apache2 logs if they exist
if [ -d "/var/log/apache2" ]; then
  cp -r /var/log/apache2 "$BACKUP_DIR/"
fi

# Check and copy syslog and auth.log files if they exist
for logfile in /var/log/syslog* /var/log/auth.log*; do
  if [ -e "$logfile" ]; then
    cp -r "$logfile" "$BACKUP_DIR/"
  fi
done

# Check and copy MySQL logs if they exist
if [ -d "/var/log/mysql" ]; then
  cp -r /var/log/mysql "$BACKUP_DIR/"
fi

# Check and copy MariaDB configuration if it exists
if [ -d "/etc/mysql/mariadb.conf.d" ]; then
  cp -r /etc/mysql/mariadb.conf.d "$BACKUP_DIR/"
fi

# Copy /var/www/html/ directory
cp -r /var/www/html "$BACKUP_DIR/"

# Check and copy modsec_audit.log if it exists
if [ -e "/var/log/modsec_audit.log" ]; then
  cp /var/log/modsec_audit.log "$BACKUP_DIR/"
fi

# Create the tar.gz archive with the backup directory
tar -czf "$ARCHIVE_NAME" "$BACKUP_DIR"

echo "Archive created: $ARCHIVE_NAME"

# Optional: Clean up by removing the backup directory
rm -rf "$BACKUP_DIR"
