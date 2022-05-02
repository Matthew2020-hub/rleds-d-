from typing_extensions import Required
from pkg_resources import require
from rest_framework import serializers

class EditProfileSerializer(serializers.Serializer):
    Full_name = serializers.CharField(required=False)
    Phone_number = serializers.CharField(required=False)
    Email = serializers.EmailField(required=False)
    Location = serializers.CharField(required=False)
    Profile_image = serializers.ImageField(required=False)
    Background_image = serializers.ImageField(required=False)