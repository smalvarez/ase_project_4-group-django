from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver

class MyAppConfig(AppConfig):
    name = 'myproject.myapp'

    def ready(self):
        # Any additional setup code
        pass
