from rest_framework import serializers
from Authentication.models import User

class EditProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'phone_number', 'profile_image','name', 'background_image']