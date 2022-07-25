from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    def setUp(self):
        self.register_url = reverse("register")
        self.login_url = reverse("login")

        self.user_data = {
            "email": "wreco@gmail.com",
            "entry": "Tenant",
            "password": "respect1242",
            "password2": "respect1242",
            "name": "string",
            "country": "AF",
            "phone_number": "+234-08102331242",
        }
        self.agent_data = {
            "email": "wrecode@gmail.com",
            "entry": "Agent",
            "password": "respect1242",
            "password2": "respect1242",
            "name": "string",
            "country": "NG",
            "phone_number": "+234-08102331242",
        }
        self.login_data = {
            "email": "wreco@gmail.com",
            "password": "respect1242",
        }
        self.forgetPassword_data = {
            "email": "wreco@gmail.com",
            "phone_number": "+234-08102331242",
            "password": "respect1241",
        }
        return super().setUp()

    def tearDown(self):
        return super().tearDown()
