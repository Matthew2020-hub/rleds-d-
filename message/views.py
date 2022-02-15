# # Create your views here.
from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.core.mail import send_mail
from .serializers import ContactUsSerailizer
import json
import os
from .models import Message
from .serializers import message_serializer
from asgiref.sync import sync_to_async
# import socketio
# from dotenv import load_dotenv
# load_dotenv()

# mgr = socketio.AsyncRedisManager(os.getenv('REDIS_URL'))
# sio = socketio.AsyncServer(async_mode="asgi", client_manager=mgr, cors_allowed_origins="*")
# # Create your views here.

# #establishes a connection with the client
# @sio.on("connect")
# async def connect(sid, env, auth):
#     if auth:
#         print("SocketIO connect")
#         sio.enter_room(sid, "feed")
#         await sio.emit("connect", f"Connected as {sid}")

# #communication with orm 
# def store_and_return_message(data):
#     data = json.loads(data)
#     instance = Message.objects.create(
#         author = data["username"],
#         message = data["message"]
#     )
#     instance.save()
#     message = message_serializer(instance)
#     return message



# # listening to a 'message' event from the client
# @sio.on('mess')
# async def print_message(sid, data):
#     print("Socket ID", sid)
#     message = await sync_to_async(store_and_return_message, thread_sensitive=True)(data) #communicating with orm
#     print(message)
#     await sio.emit("new_message", message, room="feed")



# @sio.on("disconnect")
# async def disconnect(sid):
#     print("SocketIO disconnect")











@api_view(['POST','GET'])
def contact_us(request):
    serializer = ContactUsSerailizer(data=request.data)
    if serializer.is_valid(raise_exception = True):
        sender = serializer.validated_data['sender']
        message = serializer.validated_data['message']
        send_mail(
            subject = 'Contact Form mail ' ,
            message = message,
            from_email= sender,
            recipient_list=
            ['housefree189@gmail.com'],
            fail_silently=False
        )
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)