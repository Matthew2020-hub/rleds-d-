from dataclasses import fields
from pyexpat import model
from unicodedata import category
from rest_framework import serializers
from .models import Apartment
# , Media
from django.db.models.base import ModelState
from django.db import models



# class MediaSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Media
#         fields = ["image_url"]



class ApartmentSerializer(serializers.ModelSerializer):
    # image_url = MediaSerializer(many=True)
    class Meta:
        model = Apartment
        fields = [
            "apartment_title", "category", "videofile","agent",
            "price", "location", "feautures", "descriptions",
            "location_info", "image_url","apartment_id"
            ]



class ApartmentSearchSerializer(serializers.Serializer):
    location = serializers.CharField()
    price = serializers.CharField()
    category = serializers.CharField()

    def __str__(self):
        return self.category


class ApartmentReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Apartment
        fields = ["reviews"]