from django.urls import path
from .views import (
    ApartmentCreate,
    ApartmentListUpdateDelete,
    ApartmentList,
    ApartmentSearch,
    apartment_reviews_create,
)
from django.conf import settings
from django.views.decorators.cache import cache_page
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path(
        "api/v1/apartment/post/",
        ApartmentCreate.as_view(),
        name="apartment-post",
    ),
    path(
        "api/v1/apartment/all/",
        cache_page(60*60)
        (ApartmentList.as_view())
    ),
    path(
        "api/v1/apartment/review/<uuid:apartment_id>",
        apartment_reviews_create,
        name="apartment-review",
    ),
    path(
        "api/v1/apartment/<uuid:apartment_id>",
        ApartmentListUpdateDelete.as_view(),
        name="get-apartment",
    ),
    path(
        "api/v1/apartment/search/",
        ApartmentSearch.as_view(),
        name="apartment-search",
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
