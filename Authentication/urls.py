from unicodedata import name
from django import urls
from django.urls import path, include, re_path
from .import views
from django.conf import settings
from django.conf.urls.static import static
# from allauth.account.views import confirm_email
from  .views import (
    ListAPIView, CreateDestroyAPIView, PasswordResetAPIView, 
    LogoutView, SetLoginView, CookiesLoginView, AgentCreateListAPIView, 
    AgentCreateUpdateDestroyAPIView, UserRegistration, VerifyEmail)

urlpatterns = [
    path('api/v1/user/registration/', UserRegistration.as_view()),
    path('api/v1/user/all/', UserRegistration.as_view()),
    path('api/v1/refresh-token/<str:email>', views.refreshToken, name='refresh-token'),
    path('api/v1/login/', views.login, name='login'),
    path('api/v1/user/jwt-login/', SetLoginView.as_view()),
    path('api/v1/user/jwt-logout', LogoutView.as_view()),
    path('api/v1/google-token/validate/', views.validate_authorization_code, name="code_validation"),
    path('api/v1/logout/', views.logout, name="logout"),
    path('api/v1/forget_password/<uuid:user_id>', PasswordResetAPIView.as_view()),
    path('api/v1/user/get/<uuid:user_id>', CreateDestroyAPIView.as_view()),
    path('api/v1/agent/registration/', AgentCreateListAPIView.as_view()),
    path('api/v1/agent/get/<uuid:user_id>', AgentCreateUpdateDestroyAPIView.as_view()),
    path('api/v1/logout-jwt/', LogoutView.as_view()),
    path('api/v1/login/cookies/', CookiesLoginView.as_view()),
    path('api/v1/email-verify/', VerifyEmail.as_view(), name="verify-email"),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

