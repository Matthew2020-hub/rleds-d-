from unicodedata import name
from django import urls
from django.urls import path, include, re_path
from .import views
from django.conf import settings
from django.conf.urls.static import static
# from allauth.account.views import confirm_email
from  .views import (CreateListAPIView, Login, 
CreateUpdateDestroyAPIView,CreateUpdateAPIView, LogoutView, SetLoginView, CookiesLoginView)
# from dev.settings import AUTHENTICATION_BACKENDS
# amen
urlpatterns = [
    path('api/v1/user/registration/', CreateListAPIView.as_view()),
    path('api/v1/user/login/', Login.as_view()),
    path('api/v1/user/jwt-login/', SetLoginView.as_view()),
    path('api/v1/user/logout/', LogoutView.as_view()),
    path('api/v1/user/cookies/', CookiesLoginView.as_view()),
    path('api/v1/user/access-token/', views.validate_authorization_code, name="code_validation"),
    path('rest_auth/logout/', views.logout, name="logout"),
    path('rest_auth/forget_password/<uuid:user_id>', CreateUpdateAPIView.as_view()),
    path('rest_auth/registration/<uuid:user_id>', CreateUpdateDestroyAPIView.as_view()),
    path('views/<uuid:user_id>', CreateUpdateDestroyAPIView.as_view()),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

