from django import forms
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect, get_object_or_404

from apps.home.models import AD, UserProfile


class UploadFileForm(forms.Form):
    file = forms.FileField()

class ADForm(forms.ModelForm):
    class Meta:
        model = AD
        fields = ['nom', 'type', 'description']

User = get_user_model()



class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['first_name', 'last_name', 'address', 'city', 'country', 'postal_code', 'about_me']
