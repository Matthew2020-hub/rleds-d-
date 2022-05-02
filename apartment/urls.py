from django import urls
from django.urls import path
from .views import (
    ApartmentCreateListAPIView, 
    ApartmentCreateUpdateDestroyAPIView,
    ApartmentListAPIView,
    ListAllApartmentAPIView
)
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path('api/v1/apartment/post/', ApartmentCreateListAPIView.as_view(), name='apartment-post'),
    path('api/v1/apartment/all/', ListAllApartmentAPIView.as_view(), name='apartment-list'),
    path('api/v1/apartment/<uuid:apartment_id>', ApartmentCreateUpdateDestroyAPIView.as_view(), name='get-apartment'),
    path('api/v1/apartment/search/', ApartmentListAPIView.as_view(), name='apartment-search')
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
