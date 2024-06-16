from django.contrib import admin
from django.urls import path
from myproject.myapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('recipes/', views.recipes, name='recipes'),
    path('thankyou/', views.thankyou, name='thankyou'),
    path('new_recipe/', views.new_recipe, name='new_recipe'),
    path('add_recipe/', views.add_recipe, name='add_recipe'),
    path('remove_recipe/', views.remove_recipe, name='remove_recipe'),
]
