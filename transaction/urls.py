from django import urls
from django.urls import path
from .import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('api/v1/make-payment/', views.make_payment, name='make_payment'),
    path('api/v1/verify-transaction/', views.verify_transaction, name='verify_payment'),
    path('api/v1/agent-withdraw/', views.agent_withdrawal, name='verify_payment'),
    path('api/v1/agent-balance/', views.dashboard, name='balance'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
