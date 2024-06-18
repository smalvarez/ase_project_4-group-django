from django.apps import AppConfig
from django.db import connection
from django.db.models.signals import post_migrate
from django.dispatch import receiver

class MyAppConfig(AppConfig):
    name = 'myproject.myapp'

    def ready(self):
        post_migrate.connect(create_recipe_table_if_not_exists, sender=self)

@receiver(post_migrate)
def create_recipe_table_if_not_exists(sender, **kwargs):
    table_name = 'myapp_recipe'
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_name = %s
            );
        """, [table_name])
        exists = cursor.fetchone()[0]

        if not exists:
            cursor.execute(f"""
                CREATE TABLE {table_name} (
                    id serial PRIMARY KEY,
                    name varchar(80) NOT NULL,
                    ingredients text NOT NULL,
                    steps text NOT NULL
                );
            """)
            print(f'Table {table_name} created successfully')
        else:
            print(f'Table {table_name} already exists')

