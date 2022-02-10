from django.shortcuts import render

# Create your views here.
from django.http.response import JsonResponse
from django.shortcuts import render
from .serializers import ApartmentSerializer
from .models import Apartment
from django.shortcuts import get_object_or_404
# Create your views here.
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated





class CreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request):
        check = Apartment.objects.all()

        return self.list(check)

    def post(self, request):
        return self.create(request)

class CreateUpdateDestroyAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'apartment_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, apartment_id):

        queryset = Apartment.objects.filter(apartment_id = apartment_id)
        article = get_object_or_404(queryset)
        serializer = ApartmentSerializer(article)
        return Response(serializer.data)

    def put(self, request, apartment_id):
        query = Apartment.objects.filter(apartment_id=apartment_id)
        if query:
            return self.update(request)
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, apartment_id):
        query = Apartment.objects.get(apartment_id=apartment_id)
        if query:
            return self.destroy(request)
    

