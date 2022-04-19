from .models import Profile
from rest_framework import serializers

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['user_profile']




class EditProfileSerializer(serializers.Serializer):
    First_name = serializers.CharField()
    Last_name = serializers.CharField()
    Email = serializers.EmailField()
    Location = serializers.CharField()
    Profile_image = serializers.ImageField()
    Background_image = serializers.ImageField()