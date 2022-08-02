from rest_framework import serializers
from .models import Apartment


class ApartmentSerializer(serializers.ModelSerializer):
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

    def save(self):
        apartment = Apartment(
            apartment_title=self.validated_data["apartment_title"],
            category=self.validated_data["category"],
            videofile=self.validated_data["videofile"],
            agent=self.validated_data["agent"],
            price=self.validated_data["price"],
            location=self.validated_data["location"],
            feautures=self.validated_data["feautures"],
            descriptions=self.validated_data["descriptions"],
            location_info=self.validated_data["location_info"],
            image_url=self._validated_data["image_url"],
        )
        apartment.save()


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
