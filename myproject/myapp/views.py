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

def get_recipe(request, recipe_id):
    recipe = get_object_or_404(Recipe, id=recipe_id)
    ingredients = recipe.ingredients.split('\n')
    steps = recipe.steps.split('\n')
    return render(request, 'get_recipe.html', {
        'recipe': recipe,
        'ingredients': ingredients,
        'steps': steps
    })

def get_recipe_by_query(request):
    recipe_id = request.GET.get('recipe_id')
    if recipe_id is not None:
        try:
            recipe_id = int(recipe_id)  # Convert to integer and handle potential ValueError
            recipe = Recipe.objects.get(id=recipe_id)
            ingredients = recipe.ingredients.split('\n')
            steps = recipe.steps.split('\n')
            return render(request, 'get_recipe.html', {
                'recipe': recipe,
                'ingredients': ingredients,
                'steps': steps
            })
        except (ValueError, Recipe.DoesNotExist):
            raise Http404("Recipe does not exist")
    else:
        raise Http404("No recipe ID provided")

def new_recipe(request):
    return render(request, 'new_recipe.html')

def add_recipe(request):
    if request.method == "POST":
        recipe_name = request.POST.get("recipe_name")
        ingredients = request.POST.get("ingredients")
        steps = request.POST.get("steps")
        new_recipe = Recipe(name=recipe_name, ingredients=ingredients, steps=steps)
        new_recipe.save()
        return HttpResponseRedirect(f'{reverse("thankyou")}?recipe_name={recipe_name}&ingredients={ingredients}&steps={steps}')
    else:
        return HttpResponseRedirect(reverse('new_recipe'))  # Redirect to new_recipe if not POST

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def post_recipe(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            recipe_name = data.get("recipe_name")
            ingredients = data.get("ingredients")
            steps = data.get("steps")
            new_recipe = Recipe(name=recipe_name, ingredients=ingredients, steps=steps)
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
            if not id:
                return JsonResponse({'status': 'error', 'message': 'No recipe ID provided'}, status=400)
            try:
                id = int(id)
            except ValueError:
                return JsonResponse({'status': 'error', 'message': 'Invalid recipe ID'}, status=400)
            recipe = Recipe.objects.get(id=id)
            recipe.delete()
            return JsonResponse({'status': 'success'})
        except Recipe.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Recipe not found'}, status=404)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)


def thankyou(request):
    recipe_name = request.GET.get("recipe_name", "Unknown")
    ingredients = request.GET.get("ingredients", "Unknown")
    steps = request.GET.get("steps", "Unknown")
    return render(request, 'thankyou.html', {'recipe_name': recipe_name, 'ingredients': ingredients, 'steps': steps})

def remove_recipe(request):
    if request.method == "POST":
        recipe_ids = request.POST.getlist("recipe_ids")
        Recipe.objects.filter(id__in=recipe_ids).delete()
        return redirect('recipes')
    all_recipes = Recipe.objects.all()
    return render(request, 'remove_recipe.html', {'recipes': all_recipes})
