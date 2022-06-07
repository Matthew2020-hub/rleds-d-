from unicodedata import category
from rest_framework import serializers
from .models import Apartment
from django.db.models.base import ModelState
from django.db import models

class ApartmentSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        kwargs['partial'] = True
        super(ApartmentSerializer, self).__init__(*args, **kwargs)
    class Meta:
        model = Apartment
        fields = "__all__"
class ApartmentSearchSerializer(serializers.Serializer):
    location = serializers.CharField()
    price = serializers.CharField()
    category = serializers.CharField()

    def __str__(self):
        return self.category