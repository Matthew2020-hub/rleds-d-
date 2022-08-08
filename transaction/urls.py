from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path(
        "api/v1/make-payment/",
        views.MakePayment.as_view(),
        name="make_payment",
    ),
    path(
        "api/v1/verify_transaction/<int:transaction_id>",
        views.VerifyTransaction.as_view(),
        name="verify_payment",
    ),
    path(
        "api/v1/agent/withdraw/",
        views.AgentWithdrawal.as_view(),
        name="verify_payment",
    ),
    path("api/v1/agent/balance/", views.AgentBalance, name="balance"),
    path("api/v1/transaction/history/all/", views.AllTransactionHistory.as_view()),
    path(
        "api/v1/user/<str:user_id>/payment-history",
        views.UserTransactionHistory.as_view(),
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
