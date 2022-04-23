from django import urls
from django.urls import path, include
from .import views
from django.conf import settings
from django.conf.urls.static import static

# adjacent

urlpatterns =[
    path('api/v1/profile/<str:email>', views.profile, name='profile')
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

