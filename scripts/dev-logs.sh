#!/bin/bash

# Development logs script
echo "📋 Showing development logs..."

if [ "$1" = "app" ]; then
    echo "🔍 Application logs:"
    docker-compose logs -f app
elif [ "$1" = "db" ]; then
    echo "🗄️  Database logs:"
    docker-compose logs -f mysql
elif [ "$1" = "nginx" ]; then
    echo "🌐 Nginx logs:"
    docker-compose logs -f nginx
else
    echo "📊 All service logs:"
    docker-compose logs -f
fi
