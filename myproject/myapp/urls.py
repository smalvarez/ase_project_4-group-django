from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('recipes/', views.recipes, name='recipes'),
    path('recipe/<int:id>/', views.get_recipe, name='get_recipe'),
    path('get_recipe/<int:id>/', views.get_recipe, name='get_recipe_by_id'),
    path('get_recipe/', views.get_recipe, name='get_recipe_by_query'),
    path('new_recipe/', views.new_recipe, name='new_recipe'),
    path('add_recipe/', views.add_recipe, name='add_recipe'),
    path('post_recipe/', views.post_recipe, name='post_recipe'),
    path('delete_recipe/', views.delete_recipe, name='delete_recipe'),
    path('thankyou/', views.thankyou, name='thankyou'),
    path('remove_recipe/', views.remove_recipe, name='remove_recipe'),
    path('get_all_recipes/', views.get_all_recipes, name='get_all_recipes'),
]
