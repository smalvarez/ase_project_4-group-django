import psycopg2
import subprocess
import os
from django.conf import settings
from django.core.wsgi import get_wsgi_application

# Setup Django application environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")
application = get_wsgi_application()

def create_database():
    # Connect to the default 'postgres' database to create the desired database
    conn = psycopg2.connect(
        dbname='postgres',
        user=settings.DATABASES['default']['USER'],
        password=settings.DATABASES['default']['PASSWORD'],
        host=settings.DATABASES['default']['HOST'],
        port=settings.DATABASES['default']['PORT'],
    )
    conn.autocommit = True
    cursor = conn.cursor()
    
    # Check if the database already exists
    cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{settings.DATABASES['default']['NAME']}'")
    exists = cursor.fetchone()
    
    if not exists:
        # Create the database if it doesn't exist
        cursor.execute(f"CREATE DATABASE {settings.DATABASES['default']['NAME']}")
        print(f"Database {settings.DATABASES['default']['NAME']} created successfully")
    else:
        print(f"Database {settings.DATABASES['default']['NAME']} already exists")
    
    cursor.close()
    conn.close()

def run_migrations():
    # Apply Django migrations
    subprocess.run(["python", "manage.py", "makemigrations", "myapp"])
    subprocess.run(["python", "manage.py", "migrate"])

if __name__ == "__main__":
    create_database()
    run_migrations()
