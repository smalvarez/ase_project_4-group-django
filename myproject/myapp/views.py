from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Recipe

def index(request):
    recipes = Recipe.objects.all()
    return render(request, 'index.html', {'recipes': recipes})

def about(request):
    return render(request, 'about.html')

def recipes(request):
    all_recipes = Recipe.objects.all()
    return render(request, 'recipes.html', {'recipes': all_recipes})

def thankyou(request):
    recipe_name = request.GET.get("recipe_name", "Unknown")
    ingredients = request.GET.get("ingredients", "Unknown")
    steps = request.GET.get("steps", "Unknown")
    return render(request, 'thankyou.html', {'recipe_name': recipe_name, 'ingredients': ingredients, 'steps': steps})

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

def remove_recipe(request):
    if request.method == "POST":
        recipe_ids = request.POST.getlist("recipe_ids")
        Recipe.objects.filter(id__in=recipe_ids).delete()
        return redirect('recipes')
    all_recipes = Recipe.objects.all()
    return render(request, 'remove_recipe.html', {'recipes': all_recipes})
