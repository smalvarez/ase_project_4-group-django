from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponseRedirect, Http404
from django.views.decorators.csrf import csrf_exempt
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

def recipes(request):
    all_recipes = Recipe.objects.all()
    return render(request, 'recipes.html', {'recipes': all_recipes})
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from .models import Recipe

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from .models import Recipe

def index(request):
    recipes = Recipe.objects.all()
    return render(request, 'index.html', {'recipes': recipes})

def get_recipe(request, id):
    recipe = get_object_or_404(Recipe, id=id)
    ingredients_list = recipe.ingredients.split('\n')
    steps_list = recipe.steps.split('\n')

    return JsonResponse({
        'id': recipe.id,
        'name': recipe.name,
        'ingredients': ingredients_list,
        'steps': steps_list
    })



def new_recipe(request):
    return render(request, 'new_recipe.html')


@login_required
def add_recipe(request):
    if request.method == "POST":
        name = request.POST.get("name")
        ingredients = request.POST.get("ingredients")
        steps = request.POST.get("steps")
        user = request.user  # Get the currently logged-in user

        new_recipe = Recipe(name=name, ingredients=ingredients, steps=steps, user=user)
        new_recipe.save()

        return redirect(reverse('thankyou') + f'?name={name}&ingredients={ingredients}&steps={steps}')
    else:
        return redirect(reverse('new_recipe'))


@csrf_exempt
def post_recipe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get("name")
            ingredients = data.get("ingredients")
            steps = data.get("steps")

            if not name or not ingredients or not steps:
                raise ValueError("Missing required fields")

            new_recipe = Recipe(name=name, ingredients=ingredients, steps=steps)
            new_recipe.save()
            return JsonResponse({'status': 'success'})
        except (ValueError, KeyError) as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    else:
        return JsonResponse({'status': 'invalid request'}, status=400)

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
            ingredients = data.get("ingredients")
            steps = data.get("steps")

            filter_criteria = {}
            if id is not None:
                filter_criteria['id'] = id
            if name is not None:
                filter_criteria['name__iexact'] = name
            if ingredients is not None:
                filter_criteria['ingredients__icontains'] = ingredients
            if steps is not None:
                filter_criteria['steps__icontains'] = steps

            if not filter_criteria:
                return JsonResponse({'status': 'error', 'message': 'No valid parameter provided'}, status=400)

            try:
                recipe = Recipe.objects.get(**filter_criteria)
            except Recipe.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Recipe not found'}, status=404)
            except Recipe.MultipleObjectsReturned:
                return JsonResponse({'status': 'error', 'message': 'Multiple recipes found. Provide more specific criteria.'}, status=400)

            recipe.delete()
            return JsonResponse({'status': 'success'})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

def thankyou(request):
    name = request.GET.get("name", "Unknown")
    ingredients = request.GET.get("ingredients", "Unknown")
    steps = request.GET.get("steps", "Unknown")
    return render(request, 'thankyou.html', {'name': name, 'ingredients': ingredients, 'steps': steps})

def remove_recipe(request):
    if request.method == "POST":
        recipe_ids = request.POST.getlist("recipe_ids")
        Recipe.objects.filter(id__in=recipe_ids).delete()
        return redirect('recipes')
    all_recipes = Recipe.objects.all()
    return render(request, 'remove_recipe.html', {'recipes': all_recipes})

def get_all_recipes(request):
    if request.method == 'GET':
        recipes = Recipe.objects.all()
        recipes_list = list(recipes.values())
        return JsonResponse({'recipes': recipes_list})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


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

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import logging

logger = logging.getLogger(__name__)

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
    
from django.shortcuts import render, get_object_or_404
from .models import Recipe

def recipe_detail(request, id):
    recipe = get_object_or_404(Recipe, id=id)
    ingredients_list = recipe.ingredients.split('\n')
    steps_list = recipe.steps.split('\n')

    context = {
        'recipe': recipe,
        'ingredients': ingredients_list,
        'steps': steps_list,
    }
    return render(request, 'recipe_detail.html', context)
