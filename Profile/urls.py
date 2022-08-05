from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns = [
    path("api/v1/profile/<str:email>", views.User_Profile.as_view(), name="profile")
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
