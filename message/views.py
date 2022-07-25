# Create your views here.
from ensurepip import version
from urllib import response
from django.shortcuts import get_object_or_404, render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import ContactUsSerailizer, MessageSerializer
from rest_framework.views import APIView
import os
from .models import Message, Room
from .serializers import message_serializer
from asgiref.sync import sync_to_async
import socketio
import environ
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from Authentication.models import User
from drf_yasg.utils import swagger_auto_schema
from .models import generate_short_id

# import the mailjet wrapper
from mailjet_rest import Client
import os

api_key = os.environ.get("MJ_API_KEY")
api_secret = os.environ.get("MJ_API_SECRET")

env = environ.Env()
environ.Env.read_env("housefree.env")


mgr = socketio.AsyncRedisManager(os.environ.get("REDIS_URL"))
sio = socketio.AsyncServer(
    async_mode="asgi", client_manager=mgr, cors_allowed_origins="*"
)
# Create your views here.
# establishes a connection with the client
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


# communication with orm
def store_and_return_message(data):
    data = data
    if "room_id" in data:
        room_id = data["room_id"]
    else:
        room_id = "VGTXC7NJY"
    room = Room.objects.get(room_id=room_id)
    instance = Message.objects.create(
        room=room,
        author=data["author"],
        content=data["content"],
        short_id=generate_short_id(),
    )
    instance.save()
    message = message_serializer(instance)
    return message


# listening to a 'message' event from the client
@sio.on("message")
async def print_message(sid, data):
    print("Socket ID", sid)
    print(data)
    message = await sync_to_async(store_and_return_message, thread_sensitive=True)(
        data
    )  # communicating with orm
    print(message)
    await sio.emit("new_message", message, room=message["room_id"])


class GetUserMessages(APIView):
    permission_classes = [AllowAny]

    def get(self, request, email):
        user = get_object_or_404(User, email=email)
        room = get_object_or_404(Room, user=user)
        messages = room.messages
        serializer = MessageSerializer(messages, many=True)
        response = {}
        response["room_id"] = room.room_id
        response["messages"] = serializer.data
        return Response(response, status=status.HTTP_200_OK)


class GetMessages(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(responses={200: MessageSerializer(many=True)})
    def get(self, request, email):
        user = get_object_or_404(User, email=email)
        room = get_object_or_404(Room, user=user)
        messages = room.messages
        serializer = MessageSerializer(messages, many=True)
        response = {}
        response["room_id"] = room.room_id
        response["messages"] = serializer.data
        return Response(response, status=status.HTTP_200_OK)






@api_view(["POST"])
def contact_us(request):
    serializer = ContactUsSerailizer(data=request.data)
    serializer.is_valid(raise_exception=True)
    sender = serializer.validated_data["sender"]
    message = serializer.validated_data["message"]
    mailjet = Client(auth=(api_key, api_secret), version="v3.1")
    data = {
        "Messages": [
            {
                "From": {"Email": f"{sender}", "Name": "Me"},
                "To": [{"Email": "free_house@yahoo.com", "Name": "You"}],
                "Subject": "Contact Form Mail",
                "TextPart": "Greetings from Mailjet!",
                "HTMLPart": f"<h3>{message}</h3>",
            }
        ]
    }
    result = mailjet.send.create(data=data)
    return Response(result.json(), status=status.HTTP_201_CREATED)
