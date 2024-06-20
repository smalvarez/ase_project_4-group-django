@echo off
SETLOCAL

REM Set environment variables
SET DB_NAME=recipe_db
SET DB_USER=your_db_user
SET DB_PASSWORD=your_db_password
SET DB_HOST=localhost
SET DB_PORT=5432

REM Create the database if it doesn't exist
psql -U %DB_USER% -h %DB_HOST% -p %DB_PORT% -c "SELECT 1 FROM pg_database WHERE datname='%DB_NAME%'" | find "1" >nul
IF ERRORLEVEL 1 psql -U %DB_USER% -h %DB_HOST% -p %DB_PORT% -c "CREATE DATABASE %DB_NAME%"

REM Run Django migrations
python manage.py makemigrations
python manage.py migrate

REM Start the Django development server
python manage.py runserver

ENDLOCAL
