from dataclasses import fields
from unicodedata import category
from rest_framework import serializers
from .models import Apartment, Media
from django.db.models.base import ModelState
from django.db import models



class MediaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Media
        fields = ["image_url"]



class ApartmentSerializer(serializers.ModelSerializer):
    image_url = MediaSerializer(many=True)
    depth = 2
    class Meta:
        model = Apartment
        fields = [
            "apartment_title", "category", "videofile","agent",
            "price", "location", "feautures", 
            "location_info", "image_url"
            ]

    def save(self, validated_data):
        get_image_url = self.validated_data.pop('image_url') 
        apartment = Apartment.objects.create(**self.validated_data)
        for image in get_image_url:
            Media.objects.create(apartment=apartment, **image)
        created_apartment = {
            "apartment": apartment,
            "image": get_image_url
        }
        return created_apartment




class ApartmentsSerializer(serializers.ModelSerializer):
    apartment_serializer = ApartmentSerializer(many=True)
    media_serializer = MediaSerializer(many=True)

    class Meta:
        model = Media
        fields = "__all__"


class ApartmentSearchSerializer(serializers.Serializer):
    location = serializers.CharField()
    price = serializers.CharField()
    category = serializers.CharField()

    def __str__(self):
        return self.category