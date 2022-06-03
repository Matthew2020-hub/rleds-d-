from typing_extensions import Required
from xml.parsers.expat import model
from attr import fields
from pkg_resources import require
from rest_framework import serializers
from .models import Profile

class EditProfileSerializer(serializers.Serializer):
    class Meta:
        model = Profile
        fields = "__all__"