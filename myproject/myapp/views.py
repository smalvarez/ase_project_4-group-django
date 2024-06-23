from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponseRedirect, Http404
from django.contrib.auth import authenticate, update_session_auth_hash, login as auth_login
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .models import User  # Import the custom User model
from .models import Recipe
from .forms import ProfileUpdateForm, DeleteAccountForm, PasswordChangeFormCustom
import json
import bcrypt
import jwt
from datetime import datetime, timedelta
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Review
from .serializers import ReviewSerializer
from django.shortcuts import get_object_or_404
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.http import Http404
from .models import ShopItem
from .serializers import ShopItemSerializer
from urllib.parse import urlencode
from django.shortcuts import get_object_or_404, get_list_or_404



import logging

logger = logging.getLogger(__name__)

@csrf_exempt
@require_http_methods(["POST"])
def signup(request):
    try:
        data = json.loads(request.body)
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if not first_name or not last_name or not email or not password:
            return JsonResponse({'message': 'All fields are required.'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'message': 'Email already exists.'}, status=409)

        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password  # Directly using Django's password hasher
        )

        user.save()
        return JsonResponse({'message': 'Signup successful.'}, status=200)
    except Exception as e:
        return JsonResponse({'message': f'Error signing up: {str(e)}'}, status=500)
    
@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'message': 'Email and password are required.'}, status=400)

        user = authenticate(request, username=email, password=password)
        logger.debug(f"Authenticating user: {email}")

        if user is None:
            logger.debug(f"Failed authentication for user: {email}")
            return JsonResponse({'message': 'Invalid email or password.'}, status=401)

        auth_login(request, user)  # This logs the user in and creates a session

        token = jwt.encode({'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=1)}, settings.SECRET_KEY, algorithm='HS256')
        logger.debug(f"Login successful for user: {email}")

        return JsonResponse({'message': 'Login successful.', 'token': token}, status=200)
    except Exception as e:
        logger.exception(f"Error logging in: {str(e)}")
        return JsonResponse({'message': f'Error logging in: {str(e)}'}, status=500)

@csrf_exempt
def get_profile(request):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return JsonResponse({'message': 'Authorization header missing.'}, status=401)

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        email = payload['email']

        user = User.objects.get(email=email)
        return JsonResponse({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email
        })
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired.'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token.'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'message': f'Error fetching profile: {str(e)}'}, status=500)

@csrf_exempt
@require_http_methods(["PUT"])
def update_email(request):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return JsonResponse({'message': 'Authorization header missing.'}, status=401)

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        current_email = payload['email']

        data = json.loads(request.body)
        new_email = data.get('email')

        if not current_email or not new_email:
            return JsonResponse({'message': 'Both current and new email are required.'}, status=400)

        if current_email == new_email:
            return JsonResponse({'message': 'The new email is the same as the current email. No changes made.'}, status=400)

        if User.objects.filter(email=new_email).exists():
            return JsonResponse({'message': 'New email already in use.'}, status=409)

        user = User.objects.get(email=current_email)
        user.email = new_email
        user.save()

        return JsonResponse({'message': 'Email updated successfully.'}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired.'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token.'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found.'}, status=404)
    except Exception as e:  # Consider more specific exceptions
        logging.exception(f"Error updating email: {str(e)}")
        return JsonResponse({'message': 'An error occurred while updating email.'}, status=500)

@csrf_exempt
@require_http_methods(["PUT"])
def update_password(request):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return JsonResponse({'message': 'Authorization header missing.'}, status=401)

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        email = payload['email']

        data = json.loads(request.body)
        old_password = data.get('oldPassword')
        new_password = data.get('newPassword')

        if not old_password or not new_password:
            return JsonResponse({'message': 'Old password and new password are required.'}, status=400)

        user = authenticate(request, username=email, password=old_password)

        if user is None:
            return JsonResponse({'message': 'Incorrect old password.'}, status=401)

        user.set_password(new_password)
        user.save()

        return JsonResponse({'message': 'Password updated successfully.'}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired.'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token.'}, status=401)
    except Exception as e:
        return JsonResponse({'message': f'Error updating password: {str(e)}'}, status=500)

@csrf_exempt
@require_http_methods(["PUT"])
def update_name(request):
    try:
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return JsonResponse({'message': 'Authorization header is required.'}, status=400)
        
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        current_email = payload['email']

        data = json.loads(request.body)
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        new_email = data.get('newEmail')

        if not first_name or not last_name or not new_email:
            return JsonResponse({'message': 'First name, last name, and new email are required.'}, status=400)

        if User.objects.filter(email=new_email).exists() and new_email != current_email:
            return JsonResponse({'message': 'New email already in use.'}, status=409)

        user = User.objects.get(email=current_email)
        user.first_name = first_name
        user.last_name = last_name
        user.email = new_email
        user.save()

        return JsonResponse({'message': 'Name and email updated successfully.'}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired.'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token.'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'message': f'Error updating name and email: {str(e)}'}, status=500)
    
@csrf_exempt
@require_http_methods(["DELETE"])
def delete_account(request):
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return JsonResponse({'message': 'Authorization header missing.'}, status=401)

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        email = payload['email']

        user = User.objects.get(email=email)
        user.delete()

        return JsonResponse({'message': 'User deleted successfully.'}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'message': 'Token has expired.'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'message': 'Invalid token.'}, status=401)
    except User.DoesNotExist:
        return JsonResponse({'message': 'User not found.'}, status=404)
    except Exception as e:
        logging.exception(f"Error deleting user: {str(e)}")
        return JsonResponse({'message': f'Error deleting user: {str(e)}'}, status=500)

def index(request):
    recipes = Recipe.objects.all()
    return render(request, 'index.html', {'recipes': recipes})



def about(request):
    return render(request, 'about.html')

# Recipe routes

@csrf_exempt
@require_http_methods(["POST"])
def post_recipe(request):
    try:
        data = json.loads(request.body)
        name = data.get("name")
        description = data.get("description")
        imageurl = data.get("imageurl")
        category = data.get("category")
        ingredients = data.get("ingredients")
        instructions = data.get("instructions")

        if not name or not description or not imageurl or not category or not ingredients or not instructions:
            return JsonResponse({'status': 'error', 'message': 'Missing required fields'}, status=400)

        new_recipe = Recipe(
            name=name,
            description=description,
            imageurl=imageurl,
            category=category,
            ingredients="\n".join(ingredients),
            instructions="\n".join(instructions)
            
        )
        new_recipe.save()
        return JsonResponse({'status': 'success', 'recipeid': new_recipe.id}, status=201)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def recipes(request):
    all_recipes = Recipe.objects.all()
    return render(request, 'recipes.html', {'recipes': all_recipes})


# Function to handle recipe deletion

@csrf_exempt
def delete_recipe(request):
    if request.method in ["DELETE", "POST"]:
        try:
            if request.method == "POST":
                data = json.loads(request.body)
            else:
                data = request.DELETE

            id = data.get("id")
            name = data.get("name")
            description = data.get("description")
            imageurl = data.get("imageurl")
            category = data.get("category")
            ingredients = data.get("ingredients")
            instructions = data.get("instructions")

            # Build the filter criteria based on the provided data
            filter_criteria = {}
            if id is not None:
                filter_criteria['id'] = id
            if name is not None:
                filter_criteria['name__iexact'] = name
            if description is not None:
                filter_criteria['description__icontains'] = description
            if imageurl is not None:
                filter_criteria['imageurl__iexact'] = imageurl
            if category is not None:
                filter_criteria['category__iexact'] = category
            if ingredients is not None:
                filter_criteria['ingredients__icontains'] = ingredients
            if instructions is not None:
                filter_criteria['instructions__icontains'] = instructions

            # Ensure at least one filter criteria is provided
            if not filter_criteria:
                return JsonResponse({'status': 'error', 'message': 'No valid parameter provided'}, status=400)

            # Retrieve the recipe based on the filter criteria
            try:
                recipe = Recipe.objects.get(**filter_criteria)
            except Recipe.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Recipe not found'}, status=404)
            except Recipe.MultipleObjectsReturned:
                return JsonResponse({'status': 'error', 'message': 'Multiple recipes found. Provide more specific criteria.'}, status=400)

            # Delete the found recipe
            recipe.delete()
            return JsonResponse({'status': 'success'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)


@csrf_exempt
def remove_recipe(request):
    if request.method == "POST":
        # Correctly get the list of recipe IDs from the POST data
        recipeids = request.POST.getlist('recipe_ids')
        
        if recipeids:
            # Convert the recipe IDs to integers
            recipeids = [int(id) for id in recipeids]
            
            # Filter recipes using the list of IDs
            deleted_recipes = Recipe.objects.filter(id__in=recipeids)
            
            if deleted_recipes.exists():
                recipe_names = ', '.join([recipe.name for recipe in deleted_recipes])
                recipe_descriptions = ', '.join([recipe.description for recipe in deleted_recipes])
                recipe_categories = ', '.join([recipe.category for recipe in deleted_recipes])
                recipe_imageurls = ', '.join([recipe.imageurl for recipe in deleted_recipes])
                recipe_ingredients = ' | '.join([recipe.ingredients for recipe in deleted_recipes])
                recipe_instructions = ' | '.join([recipe.instructions for recipe in deleted_recipes])
                
                # Delete recipes after collecting details
                deleted_recipes.delete()
                
                # Prepare query parameters
                query_params = urlencode({
                    'name': recipe_names,
                    'description': recipe_descriptions,
                    'category': recipe_categories,
                    'imageurl': recipe_imageurls,
                    'ingredients': recipe_ingredients,
                    'instructions': recipe_instructions
                })
                
                return redirect(f'/thankyou/?{query_params}')
    
    recipes = Recipe.objects.all()
    return render(request, 'remove_recipe.html', {'recipes': recipes})

def thankyou(request):
    # Retrieve query parameters from the request
    name = request.GET.get("name", "Unknown")
    description = request.GET.get("description", "Unknown")
    category = request.GET.get("category", "Unknown")
    imageurl = request.GET.get("imageurl", "Unknown")
    ingredients = request.GET.get("ingredients", "Unknown")
    instructions = request.GET.get("instructions", "Unknown")

    # Pass the parameters to the template context
    context = {
        'name': name,
        'description': description,
        'category': category,
        'imageurl': imageurl,
        'ingredients': ingredients,
        'instructions': instructions
    }
    
    # Render the thankyou template with the provided context
    return render(request, 'thankyou.html', context)

# Add other view functions here
@csrf_exempt
@require_http_methods(["GET"])
def get_all_recipes(request):
    try:
        recipes = Recipe.objects.all()
        recipes_list = [
            {
                'id': recipe.id,
                'name': recipe.name,
                'description': recipe.description,
                'imageurl': recipe.imageurl,
                'category': recipe.category,
                'ingredients': recipe.ingredients.split('\n'),
                'instructions': recipe.instructions.split('\n')
            } for recipe in recipes
        ]
        return JsonResponse({'recipes': recipes_list}, status=200)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    

    
@csrf_exempt
@require_http_methods(["GET"])
def get_recipe(request, id=None):
    # Initialize query parameters
    query_params = {}

    # Retrieve parameters from GET request
    if id is None:
        id = request.GET.get('id')
    name = request.GET.get('name')
    description = request.GET.get('description')
    imageurl = request.GET.get('imageurl')
    category = request.GET.get('category')
    ingredients = request.GET.get('ingredients')
    instructions = request.GET.get('instructions')

    # Try to convert id to integer if it's provided
    if id is not None:
        try:
            id = int(id)
            query_params['id'] = id
        except ValueError:
            raise Http404("Invalid recipe ID")
    
    # Add other query parameters
    if name is not None:
        query_params['name__iexact'] = name
    if description is not None:
        query_params['description__icontains'] = description
    if imageurl is not None:
        query_params['imageurl__icontains'] = imageurl
    if category is not None:
        query_params['category__iexact'] = category
    if ingredients is not None:
        query_params['ingredients__icontains'] = ingredients
    if instructions is not None:
        query_params['instructions__icontains'] = instructions

    # Retrieve recipes by any or all parameters
    if query_params:
        recipes = get_list_or_404(Recipe, **query_params)
    else:
        raise Http404("No valid query parameter provided")

    recipes_list = [{
        'id': recipe.id,
        'name': recipe.name,
        'description': recipe.description,
        'imageurl': recipe.imageurl,
        'category': recipe.category,
        'ingredients': recipe.ingredients.split('\n'),
        'instructions': recipe.instructions.split('\n')
    } for recipe in recipes]

    return JsonResponse(recipes_list, safe=False, status=200)
 

def add_recipe(request):
    if request.method == "POST":
        name = request.POST.get("name")
        description = request.POST.get("description")
        imageurl = request.POST.get("imageurl")
        category = request.POST.get("category")
        ingredients = request.POST.get("ingredients")
        instructions = request.POST.get("instructions")
        
        new_recipe = Recipe(
            name=name,
            description=description,
            imageurl=imageurl,
            category=category,
            ingredients=ingredients,
            instructions=instructions
        )
        new_recipe.save()
        
        return HttpResponseRedirect(
            f'{reverse("thankyou_add")}?name={name}&description={description}&imageurl={imageurl}&category={category}&ingredients={ingredients}&instructions={instructions}'
        )
    else:
        return render(request, 'add_recipe.html')  # Render the form for GET requests


def thankyou_add(request):
    name = request.GET.get("name", "Unknown")
    description = request.GET.get("description", "Unknown")
    imageurl = request.GET.get("imageurl", "Unknown")
    category = request.GET.get("category", "Unknown")
    ingredients = request.GET.get("ingredients", "Unknown")
    instructions = request.GET.get("instructions", "Unknown")
    
    return render(request, 'thankyou_add.html', {
        'name': name,
        'description': description,
        'imageurl': imageurl,
        'category': category,
        'ingredients': ingredients,
        'instructions': instructions
    })




def new_recipe(request):
    return render(request, 'new_recipe.html')

def recipes(request):
    all_recipes = Recipe.objects.all()
    return render(request, 'recipes.html', {'recipes': all_recipes})

def profile_settings(request):
    if request.method == 'POST':
        profile_form = ProfileUpdateForm(request.POST, instance=request.user)
        password_form = PasswordChangeFormCustom(request.user, request.POST)
        delete_form = DeleteAccountForm(request.POST)

        if profile_form.is_valid():
            profile_form.save()
            return redirect('profile_settings')

        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)  # Update session for new password
            return redirect('profile_settings')

        if delete_form.is_valid():
            user = request.user
            user.delete()  # Account deletion logic
            return redirect('logout')

    else:
        profile_form = ProfileUpdateForm(instance=request.user)
        password_form = PasswordChangeFormCustom(request.user)
        delete_form = DeleteAccountForm()

    context = {
        'profile_form': profile_form,
        'password_form': password_form,
        'delete_form': delete_form,
    }
    return render(request, 'profile_settings.html', context)


@login_required
def get_user_info(request):
    if request.method == 'GET':
        user = request.user
        logger.debug(f"Fetching user info for: {user.email}")
        user_info = {
            'firstName': user.first_name,
            'lastName': user.last_name,
            'email': user.email,
        }
        logger.debug(f"User info: {user_info}")
        return JsonResponse(user_info)
    else:
        logger.debug("Invalid request method")
        return JsonResponse({'message': 'Invalid request method.'}, status=405)
    


def recipe_detail(request, pk):
    recipe = get_object_or_404(Recipe, pk=pk)
    return render(request, 'recipe_detail.html', {'recipe': recipe})



# views.py

# views.py
from django.shortcuts import render, get_object_or_404, redirect
from .models import Recipe

def edit_recipe(request, recipe_id):
    recipe = get_object_or_404(Recipe, id=recipe_id)
    if request.method == "POST":
        recipe.name = request.POST.get('name')
        recipe.description = request.POST.get('description')
        recipe.imageurl = request.POST.get('imageurl')
        recipe.category = request.POST.get('category')
        recipe.ingredients = request.POST.get('ingredients')
        recipe.instructions = request.POST.get('instructions')
        recipe.save()
        return redirect('/')  # Redirect to the root URL after saving the recipe

    return render(request, 'edit_recipe.html', {'recipe': recipe})



@csrf_exempt
def update_recipe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            
            # Required to identify the recipe
            recipe_id = data.get("id")
            if not recipe_id:
                return JsonResponse({'status': 'error', 'message': 'Recipe ID is required'}, status=400)
            
            # Retrieve the recipe to be updated
            try:
                recipe = Recipe.objects.get(id=recipe_id)
            except ObjectDoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Recipe not found'}, status=404)
            except MultipleObjectsReturned:
                return JsonResponse({'status': 'error', 'message': 'Multiple recipes found with the same ID'}, status=400)
            
            # Check if any fields to update are provided
            fields_to_update = ['name', 'description', 'imageurl', 'category', 'ingredients', 'instructions']
            update_data = {field: data[field] for field in fields_to_update if field in data}

            if not update_data:
                return JsonResponse({'status': 'error', 'message': 'No fields provided to update'}, status=400)

            # Update the recipe fields
            for field, value in update_data.items():
                setattr(recipe, field, value)
            
            # Save the updated recipe
            recipe.save()
            
            return JsonResponse({'status': 'success', 'message': 'Recipe updated successfully'})
        
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)




class ShopItemList(APIView):
    def get(self, request):
        items = ShopItem.objects.all()
        serializer = ShopItemSerializer(items, many=True)
        return Response({'items': serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ShopItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'item_id': serializer.instance.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ShopItemDetail(APIView):
    def get_object(self, id):
        try:
            return ShopItem.objects.get(id=id)
        except ShopItem.DoesNotExist:
            raise Http404

    def get(self, request, id):
        item = self.get_object(id)
        serializer = ShopItemSerializer(item)
        return Response(serializer.data)

    def put(self, request, id):
        item = self.get_object(id)
        serializer = ShopItemSerializer(item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'message': 'Item updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id):
        item = self.get_object(id)
        item.delete()
        return Response({'status': 'success', 'message': 'Item deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import ShopItemSerializer
import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
def post_shop_item(request):
    serializer = ShopItemSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'status': 'success', 'item_id': serializer.instance.id}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def update_shop_item(request):
    if request.method == "POST":
        try:
            data = request.data
            item_id = data.get("id")
            if not item_id:
                return Response({'status': 'error', 'message': 'Item ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                item = ShopItem.objects.get(id=item_id)
            except ShopItem.DoesNotExist:
                return Response({'status': 'error', 'message': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = ShopItemSerializer(item, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'status': 'success', 'message': 'Item updated successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({'status': 'error', 'message': 'Invalid request method'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_all_shop_items(request):
    items = ShopItem.objects.all()
    serializer = ShopItemSerializer(items, many=True)
    return Response({'items': serializer.data}, status=status.HTTP_200_OK)

@api_view(['GET'])
def get_shop_item(request, id=None):
    query_params = {}
    if id is None:
        id = request.GET.get('id')
    name = request.GET.get('name')
    description = request.GET.get('description')
    price = request.GET.get('price')
    quantity = request.GET.get('quantity')
    image = request.GET.get('image')

    if id is not None:
        try:
            id = int(id)
            query_params['id'] = id
        except ValueError:
            raise Http404("Invalid item ID")
    
    if name is not None:
        query_params['name__iexact'] = name
    if description is not None:
        query_params['description__icontains'] = description
    if price is not None:
        query_params['price'] = price
    if quantity is not None:
        query_params['quantity'] = quantity
    if image is not None:
        query_params['image__iexact'] = image

    if query_params:
        items = ShopItem.objects.filter(**query_params)
        if not items.exists():
            raise Http404("No items found with the given parameters")
    else:
        raise Http404("No valid query parameter provided")

    serializer = ShopItemSerializer(items, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST', 'DELETE'])
def delete_shop_item(request):
    if request.method in ["DELETE", "POST"]:
        try:
            data = request.data

            id = data.get("id")
            name = data.get("name")
            description = data.get("description")
            price = data.get("price")
            quantity = data.get("quantity")
            image = data.get("image")

            filter_criteria = {}
            if id is not None:
                filter_criteria['id'] = id
            if name is not None:
                filter_criteria['name__iexact'] = name
            if description is not None:
                filter_criteria['description__icontains'] = description
            if price is not None:
                filter_criteria['price'] = price
            if quantity is not None:
                filter_criteria['quantity'] = quantity
            if image is not None:
                filter_criteria['image__iexact'] = image

            if not filter_criteria:
                return Response({'status': 'error', 'message': 'No valid parameter provided'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                item = ShopItem.objects.get(**filter_criteria)
            except ShopItem.DoesNotExist:
                return Response({'status': 'error', 'message': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)
            except ShopItem.MultipleObjectsReturned:
                return Response({'status': 'error', 'message': 'Multiple items found. Provide more specific criteria.'}, status=status.HTTP_400_BAD_REQUEST)

            item.delete()
            return Response({'status': 'success', 'message': 'Item deleted successfully'})

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({'status': 'error', 'message': 'Invalid request method'}, status=status.HTTP_400_BAD_REQUEST)


from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.http import Http404
from .models import Review
from .serializers import ReviewSerializer

class ReviewList(APIView):
    def get(self, request):
        reviews = Review.objects.all()
        serializer = ReviewSerializer(reviews, many=True)
        return Response({'reviews': serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'review_id': serializer.instance.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ReviewDetail(APIView):
    def get_object(self, id):
        try:
            return Review.objects.get(id=id)
        except Review.DoesNotExist:
            raise Http404

    def get(self, request, id):
        review = self.get_object(id)
        serializer = ReviewSerializer(review)
        return Response(serializer.data)

    def put(self, request, id):
        review = self.get_object(id)
        serializer = ReviewSerializer(review, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'message': 'Review updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id):
        review = self.get_object(id)
        review.delete()
        return Response({'status': 'success', 'message': 'Review deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
def create_review(request):
    serializer = ReviewSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'status': 'success', 'review_id': serializer.instance.id}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def update_review(request):
    try:
        data = request.data
        review_id = data.get("id")
        if not review_id:
            return Response({'status': 'error', 'message': 'Review ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            review = Review.objects.get(id=review_id)
        except Review.DoesNotExist:
            return Response({'status': 'error', 'message': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ReviewSerializer(review, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'message': 'Review updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_all_reviews(request):
    reviews = Review.objects.all()
    serializer = ReviewSerializer(reviews, many=True)
    return Response({'reviews': serializer.data}, status=status.HTTP_200_OK)

@api_view(['GET'])
def get_review(request, id=None):
    query_params = {}
    if id is None:
        id = request.GET.get('id')
    user_id = request.GET.get('user_id')
    username = request.GET.get('username')
    comment = request.GET.get('comment')
    liked = request.GET.get('liked')

    if id is not None:
        try:
            id = int(id)
            query_params['id'] = id
        except ValueError:
            raise Http404("Invalid review ID")

    if user_id is not None:
        query_params['user_id'] = user_id
    if username is not None:
        query_params['username__iexact'] = username
    if comment is not None:
        query_params['comment__icontains'] = comment
    if liked is not None:
        query_params['liked'] = liked.lower() == 'true'

    if query_params:
        reviews = Review.objects.filter(**query_params)
        if not reviews.exists():
            raise Http404("No reviews found with the given parameters")
    else:
        raise Http404("No valid query parameter provided")

    serializer = ReviewSerializer(reviews, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST', 'DELETE'])
def delete_review(request):
    try:
        data = request.data

        id = data.get("id")
        user_id = data.get("user_id")
        username = data.get("username")
        comment = data.get("comment")
        liked = data.get("liked")

        filter_criteria = {}
        if id is not None:
            filter_criteria['id'] = id
        if user_id is not None:
            filter_criteria['user_id'] = user_id
        if username is not None:
            filter_criteria['username__iexact'] = username
        if comment is not None:
            filter_criteria['comment__icontains'] = comment
        if liked is not None:
            filter_criteria['liked'] = liked.lower() == 'true'

        if not filter_criteria:
            return Response({'status': 'error', 'message': 'No valid parameter provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            review = Review.objects.get(**filter_criteria)
        except Review.DoesNotExist:
            return Response({'status': 'error', 'message': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)
        except Review.MultipleObjectsReturned:
            return Response({'status': 'error', 'message': 'Multiple reviews found. Provide more specific criteria.'}, status=status.HTTP_400_BAD_REQUEST)

        review.delete()
        return Response({'status': 'success', 'message': 'Review deleted successfully'})

    except Exception as e:
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
