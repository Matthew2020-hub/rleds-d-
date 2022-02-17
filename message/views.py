# Create your views here.
from urllib import response
from django.shortcuts import get_object_or_404, render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.core.mail import send_mail
from .serializers import ContactUsSerailizer, MessageSerializer
from rest_framework.views import APIView
import json
import os
from .models import Message, Room
from .serializers import message_serializer
from asgiref.sync import sync_to_async
import socketio
import environ
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from Authentication.models import User
from drf_yasg.utils import swagger_auto_schema
from .models import generate_short_id
env = environ.Env()
environ.Env.read_env('housefree.env')

mgr = socketio.AsyncRedisManager(os.environ.get('REDIS_URL'))
sio = socketio.AsyncServer(async_mode="asgi", client_manager=mgr, cors_allowed_origins="*")
# Create your views here.

#establishes a connection with the client
@sio.on("connect")
async def connect(sid, env, auth):
    if auth:
        room_id = auth["room_id"]
        print("SocketIO connect")
        sio.enter_room(sid, room_id)
        await sio.emit("connect", f"Connected as {sid}")
    else:
        room_id = "VGTXC7NJY"
        print("SocketIO connect")
        sio.enter_room(sid, room_id)
        await sio.emit("connect", f"Connected as {sid}")

#communication with orm 
def store_and_return_message(data):
    data = data
    if "room_id" in data:
        room_id = data["room_id"]
    else:
        room_id = "VGTXC7NJY"
    room = Room.objects.get(room_id=room_id)
    instance = Message.objects.create(
        room=room,
        author = data["author"],
        content = data["content"],
        short_id = generate_short_id()
    )
    instance.save()
    message = message_serializer(instance)
    return message



# listening to a 'message' event from the client
@sio.on('message')
async def print_message(sid, data):
    print("Socket ID", sid)
    print(data)
    message = await sync_to_async(store_and_return_message, thread_sensitive=True)(data) #communicating with orm
    print(message)
    await sio.emit("new_message", message, room=message["room_id"])



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

class GetUserMessages(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        room = get_object_or_404(Room, user=user)
        messages =room.messages
        serializer = MessageSerializer(messages, many=True)
        response = {}
        response["room_id"] = room.room_id
        response["messages"] = serializer.data 
        return Response(response, status=status.HTTP_200_OK)

class GetMessages(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(responses={200: MessageSerializer(many=True)})
    def get(self, request):
        print(request.user)
        user = get_object_or_404(User, email=request.user)
        room = get_object_or_404(Room, user=user)
        messages =room.messages
        serializer = MessageSerializer(messages, many=True)
        response = {}
        response["room_id"] = room.room_id
        response["messages"] = serializer.data 
        return Response(response, status=status.HTTP_200_OK)
        




