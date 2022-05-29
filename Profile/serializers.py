from typing_extensions import Required
from pkg_resources import require
from rest_framework import serializers

class EditProfileSerializer(serializers.Serializer):
    name = serializers.CharField(allow_blank=True)
    phone_number = serializers.CharField(allow_null=True)
    email = serializers.EmailField(allow_blank=True)
    # Location = serializers.CharField(allow_null=True)
    profile_image = serializers.ImageField(allow_null=True)
    background_image = serializers.ImageField(allow_null=True)