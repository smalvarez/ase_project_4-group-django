from django.db import models

class Recipe(models.Model):
    name = models.CharField(max_length=80, null=False, blank=False)
    ingredients = models.TextField(null=False, blank=False)
    steps = models.TextField(null=False, blank=False)

    def __str__(self):
        return self.name
