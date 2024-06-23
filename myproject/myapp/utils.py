import psycopg2
from django.conf import settings

def create_database():
    conn = psycopg2.connect(
        dbname='postgres',
        user=settings.DATABASES['default']['USER'],
        password=settings.DATABASES['default']['PASSWORD'],
        host=settings.DATABASES['default']['HOST'],
        port=settings.DATABASES['default']['PORT'],
    )
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{settings.DATABASES['default']['NAME']}'")
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(f"CREATE DATABASE {settings.DATABASES['default']['NAME']}")
        print(f"Database {settings.DATABASES['default']['NAME']} created successfully")
    else:
        print(f"Database {settings.DATABASES['default']['NAME']} already exists")
    cursor.close()
    conn.close()
