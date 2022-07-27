from django.urls import path
from .views import (
    ApartmentCreateAPIView,
    ApartmentCreateUpdateDestroyAPIView,
    ApartmentListAPIView,
    ApartmentSearchListAPIView,
    apartment_reviews_create,
)
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path(
        "api/v1/apartment/post/",
        ApartmentCreateAPIView.as_view(),
        name="apartment-post",
    ),
    path(
        "api/v1/apartment/all/",
        ApartmentListAPIView.as_view(),
        name="apartment-list",
    ),
    path(
        "api/v1/apartment/review/<uuid:apartment_id>",
        apartment_reviews_create,
        name="apartment-review",
    ),
    path(
        "api/v1/apartment/<uuid:apartment_id>",
        ApartmentCreateUpdateDestroyAPIView.as_view(),
        name="get-apartment",
    ),
    path(
        "api/v1/apartment/search/",
        ApartmentSearchListAPIView.as_view(),
        name="apartment-search",
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
