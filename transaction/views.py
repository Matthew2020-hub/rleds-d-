import os
from urllib import response
from django.conf import settings
from django.shortcuts import get_object_or_404, render
from locale import currency
from multiprocessing import AuthenticationError
import re
from unicodedata import name
from django.forms import ValidationError
from django.shortcuts import render
import phonenumbers
from Authentication.models import User
from apartment.models import Apartment
from apartment.pagination import CustomPagination
from .models import Payment, PaymentHistory, Rooms
from .serializers import (
    UserHistorySerializer, PaymentSerializer, 
    WithdrawalSerializer,user_paymentHistory_serializer
)
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from random import randint
import environ
import requests
from dev.settings import FLUTTERWAVE_KEY
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from asgiref.sync import sync_to_async
import socketio
from apartment.pagination import CustomPagination
from drf_yasg.utils import swagger_auto_schema
from .models import generate_short_id, Rooms
env = environ.Env()
environ.Env.read_env('housefree.env')

mgr = socketio.AsyncRedisManager(os.environ.get('REDIS_URL'))
sio = socketio.AsyncServer(
    async_mode="asgi", client_manager=mgr, 
    cors_allowed_origins="*"
    )
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
def store_and_return_payment_history(data):
    data = data
    if "room_id" in data:
        room_id = data["room_id"]
    else:
        room_id = "VGTXC7NZY"
    room = Rooms.objects.get(room_id=room_id)
    # instance = PaymentHistory.objects.filter(room=room)
    data = []
    for instant in PaymentHistory.objects.filter(room=room) :
        data.append(user_paymentHistory_serializer(instant))
    # instance.save()
    return data



# listening to a 'message' event from the client
@sio.on('message')
async def print_message(sid, data):
    print("Socket ID", sid)
    print(data)
    message = await sync_to_async(store_and_return_payment_history, thread_sensitive=True)(data) #communicating with orm
    print(message)
    await sio.emit("new_message", message, room=message["room_id"])



@api_view(['POST'])
def make_payment(request):
    serializer = PaymentSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        email = serializer.validated_data['email']
        amount = serializer.validated_data['amount']
        phone = serializer.validated_data['phone']
        name = serializer.validated_data['name']
        house_location = serializer.validated_data['House_location']
        # A try and except is used so to get the specific error as there are many
        # -conditions considered before a payment is allowed
        try:
            verify_location = get_object_or_404(Apartment, location = house_location)
        except Exception as DoesNotExist:
            return Response(
                'Transaction failed due to incorrect house address. Try again', 
                status=status.HTTP_400_BAD_REQUEST
                )
        if verify_location.is_available != True:
            return Response (
                'This Particular house is no more available', 
                status=status.HTTP_204_NO_CONTENT
                )
        agent_account_no = serializer.validated_data['agent_account_number']
        verify_agent = User.objects.filter(entry='Agent')
        try:
            verify_acct = get_object_or_404(verify_agent, user_id = agent_account_no)
        except Exception as DoesNotExist:
            return Response('Agent with this Acoount ID does not exist!', status=status.HTTP_204_NO_CONTENT)
        if verify_acct is not None:
            auth_token = FLUTTERWAVE_KEY
            hed = {'Authorization': 'Bearer ' + auth_token}
            data = {
                "tx_ref":''+str(randint(111111,999999)),
                "amount":amount,
                "currency":"NGN",
                # after payment flutterwave will call this endpoint and append to it transaction id and transaction ref
                "redirect_url":"http://localhost:8000/api/v1/verify_transaction/",
                "payment_options":"card",
                "meta":{
                        "consumer_id":agent_account_no,
                        "house_location": house_location,
                        "consumer_mac":"92a3-912ba-1192a"
                        },
                "customer":{
                    "email":email,
                    "phonenumber":phone,
                    "name":name
                    },
                "customizations":{
                "title":"Supa houseFree",
                "description":"a user-agent connct platform",
                "logo":"https://getbootstrap.com/docs/4.0/assets/brand/bootstrap-solid.svg"
                    }
                }
            url = ' https://api.flutterwave.com/v3/payments'
            response = requests.post(url, json=data, headers=hed)
            response_data = response.json()
            link=response_data['data']['link']
            return Response(link, status=status.HTTP_200_OK)
        
"""An endpoint to verify payment by calling futterwave's verification endpoint"""
@api_view(['GET']) 
def verify_transaction(request, transaction_id):
 
    response = requests.get(
        f'https://api.flutterwave.com/v3/transactions/{transaction_id}/verify',
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {FLUTTERWAVE_KEY}'},
    )
    json_response = response.json()
    response_data = json_response['data']
    get_agent_name = get_object_or_404(User, user_id=response_data['meta']['consumer_id'])
    if response_data['status'] == 'successful':
        amount = response_data['amount']
        agent = response_data['meta']['consumer_id']
        house_detail = response_data['meta']['house_location']
        verify_apartment = get_object_or_404(Apartment, location = house_detail)
        # After a successful payment, a house availability must be set to none 
        # -to avoid multiple users paying for a single apartment or building
        if verify_apartment is not None:
            verify_apartment.is_available = False
            verify_apartment.save()
            user = get_object_or_404(User, user_id=agent)
            user.balance +=amount
            user.save()  
            if get_agent_name:
                recipient = get_agent_name.name
                receiver_number = response_data['meta']['consumer_id']
                amount = response_data['amount']
                date_sent = response_data['customer']['created_at']
                sender = response_data['customer']['name']
                transaction_status = 'Successful'
                # During transaction verification, a PaymentHistory object is being created.
                create_history = PaymentHistory.objects.create(
                    sender=sender, agent_account_number=receiver_number,
                    date_sent=date_sent, amount=amount, 
                    recipient=recipient, transaction_status=transaction_status
                    )
                create_history.save()
                return Response (response_data, status=status.HTTP_200_OK)
     # A payment history object with a transaction status is  Failed is created
    recipient = get_agent_name.name
    receiver_number = response_data['meta']['consumer_id']
    amount = response_data['amount']
    date_sent = response_data['customer']['created_at']
    sender = response_data['customer']['name']
    transaction_status = 'Failed'
    create_history = PaymentHistory.objects.create(
    sender=sender, agent_account_number=receiver_number,
    date_sent=date_sent, amount=amount,
    recipient=recipient, transaction_status=transaction_status)
    create_history.save()
    verify_apartment.is_available = True
    verify_apartment.save()        
    return Response({
        'Error':'Payment Failed, Try Again!'}, 
        status=status.HTTP_400_BAD_REQUEST
        )   




"""An endpoint through which an agent could withdraw from his wallet"""
@api_view(['POST'])
def agent_withdrawal(request):
    serializer = WithdrawalSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        account_no = serializer.validated_data['account_number']
        account_bank = serializer.validated_data['account_bank']
        narration = serializer.validated_data['narration']
        currency = serializer.validated_data['currency']
        email = serializer.validated_data['email']
        amount = serializer.validated_data['amount']
        debit_currency = serializer.validated_data['debit_currency']
        acct_id = serializer.validated_data['account_id']
        account_id = User.objects.get(user_id=acct_id)
        if account_id.email !=email:
            return Response({
                'message':'Invalid Email input, enter the correct email!'}, 
                status=status.HTTP_404_NOT_FOUND
                )
        elif account_id is None:
            return Response({
                'message':'Incorrect Account ID!'}, 
                status=status.HTTP_404_NOT_FOUND
                ) 
        elif int(amount) > int(account_id.balance):
            raise ValueError("Insufficient fund")
        auth_token = FLUTTERWAVE_KEY
        header = {'Content-Type':'application/json',
            'Authorization': f'Bearer {auth_token} ' }
        data = {
            "account_bank": account_bank,
            "account_number": account_no,
            "amount":amount,
            "narration": narration,
            "currency": currency,
            "currency":"NGN",
            "reference":''+str(randint(111111,999999)),
            "callback_url":"http://localhost:8000/api/v1/verify_transaction/",
            "debit_currency":debit_currency,
            }
        url = ' https://api.flutterwave.com/v3/transfers'
        response = requests.post(url, headers=header, params=data)
        response_data = response.json()
        return Response(response_data['status'])




"""An endpoint to get Agent's Wallet balance
"""
@api_view(['GET'])
def dashboard(request):
    wallet_balance = get_object_or_404(User, email=request.user.email).balance
    context = {
            'wallet': wallet_balance
        }
    return Response(context, status=status.HTTP_200_OK)


"""User Transaction History endpoint connected to socket.io via Room connection"""
class GetUserHistoryAPIView(generics.GenericAPIView, mixins.ListModelMixin):  
    serializer_class = UserHistorySerializer
    queryset = PaymentHistory.objects.all()
    lookup_field = 'history_id'
    pagination_class = CustomPagination
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]
    @swagger_auto_schema(responses={200: UserHistorySerializer(many=True)})
    def get(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        room = get_object_or_404(Rooms, user=user)
        messages =room.messages
        serializer = UserHistorySerializer(messages, many=True)
        check = PaymentHistory.objects.filter(sender=room.user.name)
        messages =room.messages
        data = []
        for checkup in check:
            context = {
                'Sent to': checkup.recipient,
                'Agent account Number': checkup.agent_account_number,
                'Amount': checkup.amount,
                'Date': checkup.history_time,
                'Sent By': checkup.sender,
                'Transaction Status': checkup.transaction_status,
                'Alert Time': checkup.date_sent
            }
            data.append(context) 
            return Response(data, status=status.HTTP_200_OK)



class ListAPIView(generics.GenericAPIView, mixins.ListModelMixin):  
    serializer_class = UserHistorySerializer
    queryset = PaymentHistory.objects.all()
    lookup_field = 'history_id'
    pagination_class = CustomPagination
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]
    @swagger_auto_schema(responses={200: UserHistorySerializer(many=True)})
    def get(self, request):
        history = PaymentHistory.objects.all()
        data = []
        for checkup in history:
            context = {
                'Sent to': checkup.recipient,
                'Agent account Number': checkup.agent_account_number,
                'Amount': checkup.amount,
                'Date': checkup.history_time,
                'Sent By': checkup.sender,
                'Transaction Status': checkup.transaction_status,
                'Alert Time': checkup.date_sent
            }
            data.append(context) 
        return Response(data, status=status.HTTP_200_OK)
        