from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseRedirect, JsonResponse, Http404
from django.urls import reverse
from .models import Recipe
import json

def index(request):
    recipes = Recipe.objects.all()
    return render(request, 'index.html', {'recipes': recipes})

def about(request):
    return render(request, 'about.html')

def recipes(request):
    all_recipes = Recipe.objects.all()
    return render(request, 'recipes.html', {'recipes': all_recipes})

def get_recipe(request, id=None):
    # Initialize query parameters
    query_params = {}

    if id is None:
        id = request.GET.get('id')
    name = request.GET.get('name')
    ingredients = request.GET.get('ingredients')
    steps = request.GET.get('steps')

    # Try to convert id to integer if it's provided
    if id is not None:
        try:
            id = int(id)
            query_params['id'] = id
        except ValueError:
            raise Http404("Invalid recipe ID")
    
    if name is not None:
        query_params['name__iexact'] = name
    if ingredients is not None:
        query_params['ingredients__icontains'] = ingredients
    if steps is not None:
        query_params['steps__icontains'] = steps

    # Retrieve the recipe by any or all parameters
    if query_params:
        recipe = get_object_or_404(Recipe, **query_params)
    else:
        raise Http404("No valid query parameter provided")

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

def add_recipe(request):
    if request.method == "POST":
        name = request.POST.get("name")
        ingredients = request.POST.get("ingredients")
        steps = request.POST.get("steps")
        new_recipe = Recipe(name=name, ingredients=ingredients, steps=steps)
        new_recipe.save()
        return HttpResponseRedirect(f'{reverse("thankyou")}?name={name}&ingredients={ingredients}&steps={steps}')
    else:
        return HttpResponseRedirect(reverse('new_recipe'))  # Redirect to new_recipe if not POST

from django.views.decorators.csrf import csrf_exempt

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

            # Build the filter criteria based on the provided data
            filter_criteria = {}
            if id is not None:
                filter_criteria['id'] = id
            if name is not None:
                filter_criteria['name__iexact'] = name
            if ingredients is not None:
                filter_criteria['ingredients__icontains'] = ingredients
            if steps is not None:
                filter_criteria['steps__icontains'] = steps

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
