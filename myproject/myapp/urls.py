from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from myproject.myapp.views import post_shop_item
from myproject.myapp.views import ReviewList, ReviewDetail, get_all_reviews, get_review, create_review, update_review, delete_review


from myproject.myapp import views  # Make sure to replace `myapp` with the actual name of your app

urlpatterns = [    
   
    path('', views.index, name='index'),
    path('signup/', views.signup, name='signup'),
    path('api/login/', views.login, name='login'),
    path('api/get_profile/', views.get_profile, name='get_profile'),
    path('api/update_email/', views.update_email, name='update_email'),
    path('api/update_password/', views.update_password, name='update_password'),
    path('update_name/', views.update_name, name='update_name'),
    path('api/delete_account/', views.delete_account, name='delete_account'),
    path('about/', views.about, name='about'),
    path('recipes/', views.recipes, name='recipes'),
    path('recipes/edit/<int:recipe_id>/', views.edit_recipe, name='edit_recipe'),
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
    path('recipes/edit/<int:recipe_id>/', views.edit_recipe, name='edit_recipe'),
    path('recipes/<int:pk>/', views.recipe_detail, name='recipe_detail'),
    path('thankyou_add/', views.thankyou_add, name='thankyou_add'),
    path('update_recipe/', views.update_recipe, name='update_recipe'),
    path('reviews/create/', views.create_review, name='create_review'),
    path('reviews/all/', views.get_all_reviews, name='get_all_reviews'),
    path('reviews/', views.get_review, name='get_review'),
    path('reviews/update/', views.update_review, name='update_review'),
    path('reviews/delete/', views.delete_review, name='delete_review'),
    path('shop-items/', views.get_all_shop_items, name='get_all_shop_items'),
    path('shop-item/', views.get_shop_item, name='get_shop_item'),
    path('shop-item/create/', views.post_shop_item, name='post_shop_item'),
    path('shop-item/delete/', views.delete_shop_item, name='delete_shop_item'),
    path('shop-item/update/', views.update_shop_item, name='update_shop_item'),
]
