from django.shortcuts import get_object_or_404
from Authentication.models import User
from apartment.models import Apartment
from .models import PaymentHistory
from .serializers import (
    UserHistorySerializer,
    PaymentSerializer,
    WithdrawalSerializer
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
from rest_framework.permissions import AllowAny
# from apartment.pagination import CustomPagination
from drf_yasg.utils import swagger_auto_schema
env = environ.Env()
environ.Env.read_env("housefree.env")


@api_view(["POST"])
def make_payment(request):
    serializer = PaymentSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        user_email = serializer.validated_data["email"]
        amount = serializer.validated_data["amount"]
        phone = serializer.validated_data["phone"]
        name = serializer.validated_data["name"]
        apartment_id = serializer.validated_data["apartment_id"]
        # A try and except is used so to get the specific error as there are many
        # -conditions considered before a payment is allowed
        try:
            verify_location = get_object_or_404(Apartment, location=apartment_id)
        except Apartment.DoesNotExist:
            return Response(
                "Transaction failed due to incorrect house address",
                status=status.HTTP_400_BAD_REQUEST,
            )
        if verify_location.is_available != True:
            return Response(
                "This Particular house is no more available",
                status=status.HTTP_204_NO_CONTENT,
            )
        agent_email = serializer.validated_data["agent_email"]
        verify_agent = User.objects.filter(entry="Agent")
        try:
            verify_acct = get_object_or_404(verify_agent, email=agent_email)
        except User.DoesNotExist:
            return Response(
                "Agent with this Acoount ID does not exist!",
                status=status.HTTP_204_NO_CONTENT,
            )
        if verify_acct is not None:
            auth_token = FLUTTERWAVE_KEY
            hed = {"Authorization": "Bearer " + auth_token}
            data = {
                "tx_ref": "" + str(randint(111111, 999999)),
                "amount": amount,
                "currency": "NGN",
                # after payment flutterwave will call this endpoint and 
                # append to it transaction id and transaction ref
                "redirect_url": "https://freehouses.herokuapp.com/api/v1/verify_transaction/",
                "payment_options": "card",
                "meta": {
                    "consumer_id": apartment_id,
                    "agent_ID": agent_email,
                    "consumer_mac": "92a3-912ba-1192a",
                },
                "customer": {
                    "email": user_email, "phonenumber": phone, "name": name
                    },
                "customizations": {
                    "title": "Supa houseFree",
                    "description": "a user-agent connct platform",
                    "logo": "https://getbootstrap.com/docs/4.0/assets/brand/bootstrap-solid.svg",
                },
            }
            url = " https://api.flutterwave.com/v3/payments"
            response = requests.post(url, json=data, headers=hed)
            response_data = response.json()
            link = response_data["data"]["link"]
            return Response(link, status=status.HTTP_200_OK)


@api_view(["GET"])
def verify_transaction(request, transaction_id):

    """An payment verifiaction endpoint"""

    response = requests.get(
        f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {FLUTTERWAVE_KEY}",
        },
    )
    json_response = response.json()
    response_data = json_response["data"]
    get_agent_name = get_object_or_404(
        User, user_id=response_data["meta"]["consumer_id"]
    )
    if response_data["status"] == "successful":
        amount = response_data["amount"]
        agent = response_data["meta"]["consumer_id"]
        house_detail = response_data["meta"]["house_location"]
        verify_apartment = get_object_or_404(Apartment, location=house_detail)
        # After a successful payment, a house availability must be set to none
        # -to avoid multiple users paying for a single apartment or building
        if verify_apartment is not None:
            verify_apartment.is_available = False
            verify_apartment.save()
            user = get_object_or_404(User, user_id=agent)
            user.balance += amount
            user.save()
            if get_agent_name:
                recipient = get_agent_name.name
                receiver_number = response_data["meta"]["consumer_id"]
                amount = response_data["amount"]
                date_sent = response_data["customer"]["created_at"]
                sender = response_data["customer"]["name"]
                transaction_status = "Successful"
                # During transaction verification, a PaymentHistory object
                #  is being created.
                create_history = PaymentHistory.objects.create(
                    sender=sender,
                    agent_account_number=receiver_number,
                    date_sent=date_sent,
                    amount=amount,
                    recipient=recipient,
                    transaction_status=transaction_status,
                )
                create_history.save()
                return Response(response_data, status=status.HTTP_200_OK)
    # A payment history object with a transaction status is  Failed is created
    recipient = get_agent_name.name
    receiver_number = response_data["meta"]["consumer_id"]
    amount = response_data["amount"]
    date_sent = response_data["customer"]["created_at"]
    sender = response_data["customer"]["name"]
    transaction_status = "Failed"
    create_history = PaymentHistory.objects.create(
        sender=sender,
        agent_account_number=receiver_number,
        date_sent=date_sent,
        amount=amount,
        recipient=recipient,
        transaction_status=transaction_status,
    )
    create_history.save()
    verify_apartment.is_available = True
    verify_apartment.save()
    return Response(
        {"Error": "Payment Failed, Try Again!"}, 
        status=status.HTTP_400_BAD_REQUEST
    )


@api_view(["POST"])
def agent_withdrawal(request):

    """An Agent withdrawal endpoint"""\
    

    serializer = WithdrawalSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        account_no = serializer.validated_data["account_number"]
        account_bank = serializer.validated_data["account_bank"]
        narration = serializer.validated_data["narration"]
        currency = serializer.validated_data["currency"]
        email = serializer.validated_data["email"]
        amount = serializer.validated_data["amount"]
        debit_currency = serializer.validated_data["debit_currency"]
        acct_id = serializer.validated_data["account_id"]
        account_id = User.objects.get(user_id=acct_id)
        if account_id.email != email:
            return Response(
                {"message": "Invalid Email input, enter the correct email!"},
                status=status.HTTP_404_NOT_FOUND,
            )
        elif account_id is None:
            return Response(
                {"message": "Incorrect Account ID!"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        elif int(amount) > int(account_id.balance):
            raise ValueError("Insufficient fund")
        auth_token = FLUTTERWAVE_KEY
        header = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token} ",
        }
        data = {
            "account_bank": account_bank,
            "account_number": account_no,
            "amount": amount,
            "narration": narration,
            "currency": currency,
            "currency": "NGN",
            "reference": "" + str(randint(111111, 999999)),
            "callback_url": "http://localhost:8000/api/v1/verify_transaction/",
            "debit_currency": debit_currency,
        }
        url = " https://api.flutterwave.com/v3/transfers"
        response = requests.post(url, headers=header, params=data)
        response_data = response.json()
        return Response(response_data["status"])


@api_view(["GET"])
def dashboard(request):

    """An endpoint to get Agent's Wallet balance"""
    wallet_balance = get_object_or_404(User, email=request.user.email).balance
    context = {"wallet": wallet_balance}
    return Response(context, status=status.HTTP_200_OK)


class GetUserHistoryAPIView(generics.GenericAPIView, mixins.ListModelMixin):

    """User Transaction History endpoint"""

    serializer_class = UserHistorySerializer
    queryset = PaymentHistory.objects.all()
    lookup_field = "history_id"
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    @swagger_auto_schema(responses={200: UserHistorySerializer(many=True)})
    def get(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        payment_history = PaymentHistory.objects.filter(sender=user)
        return Response(
            self.serializer_class(payment_history, many=True).data,
            status=status.HTTP_200_OK,
        )


class ListAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = UserHistorySerializer
    queryset = PaymentHistory.objects.all()
    lookup_field = "history_id"
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    @swagger_auto_schema(responses={200: UserHistorySerializer(many=True)})
    def get(self, request):
        data = self.serializer_class(self.get_queryset(), many=True).data
        return Response(data, status=status.HTTP_200_OK)
