#!/bin/bash

# Development database script
echo "🗄️  Database development tools..."

if [ "$1" = "connect" ]; then
    echo "🔌 Connecting to MySQL..."
    docker-compose exec mysql mysql -u user -ppassword database
elif [ "$1" = "reset" ]; then
    echo "⚠️  Resetting database..."
    read -p "Are you sure you want to reset the database? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down
        docker volume rm huma-sample_app-data-dev 2>/dev/null || true
        docker-compose up -d
        echo "✅ Database reset complete!"
    else
        echo "❌ Database reset cancelled."
    fi
elif [ "$1" = "backup" ]; then
    echo "💾 Creating database backup..."
    BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
    docker-compose exec mysql mysqldump -u user -ppassword database > "$BACKUP_FILE"
    echo "✅ Backup created: $BACKUP_FILE"
elif [ "$1" = "adminer" ]; then
    echo "🌐 Opening Adminer in browser..."
    echo "📋 Database connection info:"
    echo "   Server: mysql"
    echo "   Username: user"
    echo "   Password: password"
    echo "   Database: database"
    open http://localhost:8080 2>/dev/null || xdg-open http://localhost:8080 2>/dev/null || echo "Please open http://localhost:8080 in your browser"
else
    echo "Usage: $0 {connect|reset|backup|adminer}"
    echo "  connect - Connect to MySQL CLI"
    echo "  reset   - Reset database (WARNING: deletes all data)"
    echo "  backup  - Create database backup"
    echo "  adminer - Open Adminer web interface"
fi
