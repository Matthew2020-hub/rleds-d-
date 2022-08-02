from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from . import tasks

urlpatterns = [
    path("api/v1/contact-us/", tasks.contact_us, name="contact_us"),
    path("api/v1/messages/<str:email>", views.GetMessages.as_view()),
    path("api/v1/user/<str:email>/messages", views.GetUserMessages.as_view()),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
