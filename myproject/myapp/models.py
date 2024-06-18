from django.db import models

class Recipe(models.Model):
    name = models.CharField(max_length=80)
    ingredients = models.TextField()
    steps = models.TextField()
