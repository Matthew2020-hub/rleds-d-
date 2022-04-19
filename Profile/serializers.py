from rest_framework import serializers

class EditProfileSerializer(serializers.Serializer):
    Full_name = serializers.CharField()
    Phone_number = serializers.CharField()
    Email = serializers.EmailField()
    Location = serializers.CharField()
    Profile_image = serializers.ImageField()
    Background_image = serializers.ImageField()