"""
ASGI config for dev project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/howto/deployment/asgi/
"""

import os

import socketio
from message.views import sio

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dev.settings")

django_asgi_app = get_asgi_application()


application = socketio.ASGIApp(sio, django_asgi_app)
