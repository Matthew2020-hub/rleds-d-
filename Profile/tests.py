from rest_framework.test import APITestCase
from django.urls import reverse
import json
import pdb
from Authentication.models import User


class TestSetUp(APITestCase):
    def setUp(self):
        self.profile_url = reverse("profile")
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
        return super().setUp()

    def test_post_apartment(self):
        user_registration = self.client.post(
            self.register_url, self.user_data, format="json"
        )
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        user_login = self.client.post(self.login_url, self.user_data, format="json")
        get_profile = self.client.get(self.profile_url)
        self.assertEqual(get_profile.status_code, 200)
        self.assertEqual(
            get_profile.data["full_name"],
            user_registration.data["data"]["name"],
        )
        self.assertEqual(get_profile.data["email"], "wreco@gmail.com")

    def tearDown(self):
        return super().tearDown()
