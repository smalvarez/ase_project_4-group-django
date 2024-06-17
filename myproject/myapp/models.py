from django.db import models

class Recipe(models.Model):
    name = models.CharField(max_length=80, null=False, blank=False)
    ingredients = models.TextField(null=False, blank=False)
    steps = models.TextField(null=False, blank=False)

    class Meta:  # Correct indentation (same as class definition)
        app_label = 'myapp'

    def __str__(self):
        return self.name
