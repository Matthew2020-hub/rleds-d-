from rest_framework import serializers
from .models import Apartment


class ApartmentSerializer(serializers.ModelSerializer):
    image_url = serializers.JSONField()
    class Meta:
        model = Apartment
        fields = [
            "apartment_title",
            "category",
            "videofile",
            "agent",
            "price",
            "location",
            "feautures",
            "descriptions",
            "location_info",
            "image_url",
            "apartment_id",
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


class ReturnApartmentInfoSerializer(serializers.ModelSerializer):
    reviews = ApartmentReviewSerializer(many=True)

    class Meta:
        depth = 1
        model = Apartment
        fields = [
            "apartment_title",
            "category",
            "videofile",
            "agent",
            "price",
            "location",
            "feautures",
            "descriptions",
            "location_info",
            "image_url",
            "apartment_id",
            "reviews",
        ]
