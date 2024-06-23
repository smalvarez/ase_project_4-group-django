from django.db import connection
from django.db.utils import OperationalError
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from .models import User, Recipe

def create_table_if_not_exists(model):
    with connection.cursor() as cursor:
        table_name = model._meta.db_table
        try:
            cursor.execute(f"SELECT 1 FROM {table_name} LIMIT 1;")
        except OperationalError:
            model._meta.managed = True
            model._default_manager.db_manager('default').create_table()
            model._meta.managed = False

@receiver(post_migrate)
def ensure_tables_exist(sender, **kwargs):
    create_table_if_not_exists(User)
    create_table_if_not_exists(Recipe)
