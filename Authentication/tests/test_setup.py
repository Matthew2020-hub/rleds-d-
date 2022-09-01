from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    def setUp(self):
        self.register_url = reverse("user-register")
        self.login_url = reverse("login")

        self.user_data = {
            "email": "wreco@gmail.com",
            "entry": "Tenant",
            "password": "Password@01",
            "name": "string",
            "country": "AF",
            "phone_number": "+2348102901245"
        }
        self.agent_data = {
            "email": "wrecode@gmail.com",
            "entry": "Agent",
            "password": "Password@01",
            "name": "string",
            "country": "NG",
            "phone_number": "+2348102901248",
        }
        self.login_data = {
            "email": "wreco@gmail.com",
            "password": "Password@01"
        }
        self.forgetPassword_data = {
            "email": "wreco@gmail.com",
            "password": "Password@01",
        }
        return super().setUp()

    def tearDown(self):
        return super().tearDown()
