from typing_extensions import Required
from pkg_resources import require
from rest_framework import serializers

class EditProfileSerializer(serializers.Serializer):
    Full_name = serializers.CharField(allow_blank=True)
    Phone_number = serializers.CharField(allow_null=True)
    Email = serializers.EmailField(allow_blank=True)
    Location = serializers.CharField(allow_null=True)
    Profile_image = serializers.ImageField(allow_null=True)
    Background_image = serializers.ImageField(allow_null=True)