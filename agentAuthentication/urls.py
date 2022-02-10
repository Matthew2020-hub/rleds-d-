from unicodedata import name
from django import urls
from django.urls import path, include
from .import views
from django.conf import settings
from django.conf.urls.static import static
from allauth.account.views import confirm_email
from  .views import (CreateListAPIView, Login, 
CreateUpdateDestroyAPIView,CreateUpdateAPIView, LogoutView, SetLoginView, CookiesLoginView)
from dev.settings import AUTHENTICATION_BACKENDS

urlpatterns = [
    path('api/v1/agent/registration/', CreateListAPIView.as_view()),
    path('api/v1/agent/<uuid:user_id>', CreateUpdateDestroyAPIView.as_view()),
    path('api/v1/agent/login/', Login.as_view(), name='agent-login'),
    path('agent/', SetLoginView.as_view()),
    path('api/v1/agent/logout/', LogoutView.as_view()),
    path('api/v1/agent/jwt-cookie/', CookiesLoginView.as_view()),
    path('api/v1/agent/access-tokens/', views.validate_authorization_code, name="code_validation"),
    path('rest_auth/logout/', views.logout, name="logout"),
    path('api/v1/agent/forget-password/<uuid:user_id>', CreateUpdateAPIView.as_view()),
    path('', include('rest_auth.urls')),
    path('agent-view/<uuid:user_id>', CreateUpdateDestroyAPIView.as_view()),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

