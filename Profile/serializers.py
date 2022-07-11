from typing_extensions import Required
from xml.parsers.expat import model
from attr import fields
from pkg_resources import require
from rest_framework import serializers
from .models import Profile
from Authentication.models import User

class EditProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'phone_number', 'profile_image','name', 'background_image']