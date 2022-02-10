from django import urls
from django.urls import path, include
# from .views import ApartmentApiView
from .views import CreateListAPIView, CreateUpdateDestroyAPIView
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path('api/v1/apartment/', CreateListAPIView.as_view()),
    path('api/v1/apartment/<uuid:apartment_id>', CreateUpdateDestroyAPIView.as_view())
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
