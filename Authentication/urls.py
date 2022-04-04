from unicodedata import name
from django import urls
from django.urls import path, include, re_path
from .import views
from django.conf import settings
from django.conf.urls.static import static
# from django.contrib import admin
# from allauth.account.views import confirm_email
from  .views import (
    GET_AND_DELETE_AGENT, GET_AND_DELETE_USER, GenerateOTP, ListUserAPIView, PasswordReset, 
    LogoutView, CookiesLoginView,  userRegistration,agentRegistration, VerifyEmail)

urlpatterns = [
    path('api/v1/user/registration/', userRegistration.as_view(), name='user-register'),
    path('api/v1/agent/registration/', agentRegistration.as_view(), name='agent-register'),
    path('api/v1/user/all/', ListUserAPIView.as_view(), name='get-users'),
    path('api/v1/refresh-token/<str:email>', views.refreshToken, name='refresh-token'),
    path('api/v1/login/', views.login_user, name='login'),
    path('api/v1/google-token/validate/', views.validate_authorization_code, name="code_validation"),
    path('api/v1/logout/', views.user_logout, name="logout"),
    path('api/v1/forget_password/<uuid:user_id>', PasswordReset.as_view()),
    path('api/v1/get-OTP/<str:email>', GenerateOTP.as_view(), name='get-OTP'),
    path('api/v1/verify-OTP/<str:code>', views.validate_OTP, name='verify-OTP'),
    path('api/v1/user/get/<uuid:user_id>', GET_AND_DELETE_USER.as_view()),
    path('api/v1/agent/get/<uuid:user_id>', GET_AND_DELETE_AGENT.as_view()),
    path('api/v1/logout-jwt/', LogoutView.as_view()),
    path('api/v1/login/cookies/', CookiesLoginView.as_view()),
    path('api/v1/email-verify/', VerifyEmail.as_view(), name="verify-email"),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

