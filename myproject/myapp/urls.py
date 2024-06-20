# urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from myproject.myapp import views  # Make sure to replace `myapp` with the actual name of your app

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/signup/', views.signup, name='signup'),
    path('api/login/', views.login, name='login'),
    path('api/get_profile/', views.get_profile, name='get_profile'),
    path('api/update_email/', views.update_email, name='update_email'),
    path('api/update_password/', views.update_password, name='update_password'),
    path('api/update_name/', views.update_name, name='update_name'),
    path('api/delete_account/', views.delete_account, name='delete_account'),
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('recipes/', views.recipes, name='recipes'),
    path('get_recipe/', views.get_recipe, name='get_recipe'),
    path('recipe/<int:id>/', views.get_recipe, name='get_recipe'),
    path('new_recipe/', views.new_recipe, name='new_recipe'),
    path('add_recipe/', views.add_recipe, name='add_recipe'),
    path('post_recipe/', views.post_recipe, name='post_recipe'),
    path('delete_recipe/', views.delete_recipe, name='delete_recipe'),
    path('thankyou/', views.thankyou, name='thankyou'),
    path('remove_recipe/', views.remove_recipe, name='remove_recipe'),
    path('get_all_recipes/', views.get_all_recipes, name='get_all_recipes'),
    path('profile_settings/', views.profile_settings, name='profile_settings'),
    path('api/get_user_info/', views.get_user_info, name='get_user_info'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
