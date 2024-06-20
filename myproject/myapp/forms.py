from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import User, UserProfile

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

class DeleteAccountForm(forms.Form):
    confirm = forms.BooleanField(required=True, label="I confirm that I want to delete my account")

class PasswordChangeFormCustom(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    confirm_new_password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_new_password = cleaned_data.get("confirm_new_password")

        if new_password and confirm_new_password:
            if new_password != confirm_new_password:
                raise forms.ValidationError("New password and confirm new password do not match.")
        return cleaned_data
