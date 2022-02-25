from django import urls
from django.urls import path, include
# from .views import ApartmentApiView
from .views import ApartmentCreateListAPIView, ApartmentCreateUpdateDestroyAPIView, ApartmentListAPIView
from .import views
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path('api/v1/apartment/post/', ApartmentCreateListAPIView.as_view()),
    path('api/v1/apartment/<uuid:apartment_id>', ApartmentCreateUpdateDestroyAPIView.as_view()),
    path('api/v1/apartment/search/', ApartmentListAPIView.as_view(), name='aprtment-search')
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
