from django.shortcuts import get_object_or_404
from Authentication.models import User
from apartment.models import Apartment
from .models import PaymentHistory
from .serializers import (
    PaymentHistorySerializer,
    PaymentSerializer,
    WithdrawalSerializer
)
from rest_framework.response import Response
from rest_framework import status
from random import randint
import environ
from rest_framework.views import APIView
import requests
from dev.settings import FLUTTERWAVE_KEY
from rest_framework import generics
from rest_framework import mixins
from rest_framework.exceptions import APIException
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
# from apartment.pagination import CustomPagination
from drf_yasg.utils import swagger_auto_schema
env = environ.Env()
environ.Env.read_env("housefree.env")




class MakePayment(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    @swagger_auto_schema(
            request_body=PaymentSerializer, 
            responses=200
            )
    def post(request):
        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_email = serializer.validated_data["email"]
            amount = serializer.validated_data["amount"]
            phone = serializer.validated_data["phone"]
            name = serializer.validated_data["name"]
            apartment_id = serializer.validated_data["apartment_id"]
            agent_email = serializer.validated_data["agent_email"]
            # A try and except is used so to get the specific error as there are many
            # -conditions considered before a payment is allowed
            try:
                verify_location = Apartment.objects.get( 
                    location=apartment_id
                    )
            except Apartment.DoesNotExist:
                raise APIException(
                   detail= "Transaction failed due to incorrect house address",
                    code=status.HTTP_400_BAD_REQUEST,
                )
            if verify_location.is_available != True:
                raise APIException(
                    detail="This Particular house is no more available",
                    code=status.HTTP_204_NO_CONTENT,
                )
            try:
                confirm_user_is_agent = User.objects.get(email=agent_email)
            except User.DoesNotExist:
                raise APIException(
                    detail="Agent with this Acoount ID does not exist!",
                    code=status.HTTP_204_NO_CONTENT,
                )
            if confirm_user_is_agent.is_admin is False:
                return Response(
                    "Only agent can lease out an apartment", 
                    status=status.HTTP_401_UNAUTHORIZED
                    ) 
            auth_token = FLUTTERWAVE_KEY
            header = {"Authorization": "Bearer " + auth_token}
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
            response = requests.post(url, json=data, headers=header)
            response_data = response.json()
            link = response_data["data"]["link"]
            return Response(link, status=status.HTTP_200_OK)




class VerifyTransaction(APIView):
    permisssion_classes = [AllowAny]
    def get(request, transaction_id):

        """An payment verifiaction endpoint"""

        response = requests.get(
            f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {FLUTTERWAVE_KEY}",
            },
        )
        json_response = response.json()
        if json_response:
            response_data = json_response["data"]
            amount = response_data["amount"]
            date_sent = response_data["customer"]["created_at"]
            sender = response_data["customer"]["name"]
            agent_id = response_data["meta"]["consumer_id"]
            house_detail = response_data["meta"]["house_location"]
            get_agent = get_object_or_404(
                User, user_id=agent_id
            )
            recipient = get_agent.name
            if get_agent.is_admin is False:
                raise APIException(
                    detail="Only an agent can lease out an apartment",
                    code=status.HTTP_401_UNAUTHORIZED
                )
            if response_data["status"] == "successful":        
                verify_apartment = get_object_or_404(
                    Apartment, location=house_detail
                    )
                verify_apartment.is_available = False
                verify_apartment.save()
                get_agent.balance += amount
                get_agent.save()
                # During transaction verification, a PaymentHistory object
                        #  is being created.
                create_history = PaymentHistory.objects.create(
                    sender=sender,
                    agent_account_number=agent_id,
                    date_sent=date_sent,
                    amount=amount,
                    recipient=recipient,
                    transaction_status="Successful",
                )
                return Response(create_history, status=status.HTTP_200_OK)                        
            create_history = PaymentHistory.objects.create(
                sender=sender,
                agent_account_number=agent_id,
                date_sent=date_sent,
                amount=amount,
                recipient=recipient,
                transaction_status="Failed",
            )
            return Response(
                {"Error": "Payment Failed, Try Again!"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        raise APIException(
            detail="Transaction ID is invalid",
            code=status.HTTP_400_BAD_REQUEST
        )


class AgentWithdrawal(APIView):

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    @swagger_auto_schema(
        request_body=WithdrawalSerializer, 
        responses=200
        )
    def post(request):

        """An Agent withdrawal endpoint"""
        
        serializer = WithdrawalSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data["email"]
            amount = serializer.validated_data["amount"]
            acct_id = serializer.validated_data["account_id"]
            account_id = User.objects.get(user_id=acct_id)
            if account_id.email != email:
                raise APIException(
                    detail="Invalid Email input, enter the correct email!",
                    code=status.HTTP_404_NOT_FOUND,
                )
            elif account_id is None:
                raise APIException(
                    detail="Incorrect Account ID!", 
                    code=status.HTTP_404_NOT_FOUND
                )
            elif int(amount) > int(account_id.balance):
                raise ValueError("Insufficient fund")
            auth_token = FLUTTERWAVE_KEY
            header = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth_token} ",
            }
            data = {
                "account_bank": serializer.validated_data['account_bank'],
                "account_number":serializer.validated_data['account_number'],
                "amount": serializer.validated_data['amount'],
                "narration": serializer.validated_data['narration'],
                "currency": serializer.validated_data['currency'],
                "currency": "NGN",
                "reference": "" + str(randint(111111, 999999)),
                "callback_url": "http://localhost:8000/api/v1/verify_transaction/",
                "debit_currency": serializer.validated_data['debit_currency'],
            }
            url = " https://api.flutterwave.com/v3/transfers"
            response = requests.post(url, headers=header, params=data)
            response_data = response.json()
            return Response(response_data["status"])



class AgentBalanceView(APIView):

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(request):

        """An endpoint to get Agent's Wallet balance"""
        wallet_balance = get_object_or_404(
            User, email=request.user.email
            ).balance
        context = {"wallet": wallet_balance}
        return Response(context, status=status.HTTP_200_OK)




class UserTransactionHistoryAPIView(APIView):

    """
        User Transaction History endpoint
    """
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    @swagger_auto_schema(
        request_body=PaymentHistorySerializer, 
        responses=status.HTTP_200_OK
        )
    def get(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        payment_history = PaymentHistory.objects.filter(sender=user)
        return Response(
            PaymentHistorySerializer(payment_history, many=True).data,
            status=status.HTTP_200_OK,
        )


class AllTransactionHistoryAPIView(APIView):

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    @swagger_auto_schema(
        request_body=PaymentHistorySerializer, 
        responses=status.HTTP_200_OK
        )      
    def get(self, request):
        
        queryset = PaymentHistory.objects.all()
        payment_data =  PaymentHistorySerializer(
            queryset, many=True
            ).data
        return Response(payment_data, status=status.HTTP_200_OK)
