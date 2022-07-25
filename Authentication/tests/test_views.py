from django.urls import reverse
import json
from .test_setup import TestSetUp
import pdb
from ..models import User


class TestViews(TestSetUp):
    def test_user_cannot_register_with_no_data(self):
        res = self.client.post(self.register_url)
        self.assertEqual(res.status_code, 400)

    def test_user_can_register(self):
        res = self.client.post(self.register_url, self.user_data, format="json")
        # pdb.set_trace()
        self.assertEqual(res.status_code, 201)

    def test_NotVerifiedUser_cannot_login(self):
        self.client.post(self.register_url, self.user_data, format="json")
        res = self.client.post(self.login_url, self.user_data, format="json")
        # pdb.set_trace()
        self.assertEqual(res.status_code, 400)

    def test_VerifiedUser_login(self):
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        res = self.client.post(self.login_url, self.user_data, format="json")
        # pdb.set_trace()
        self.assertEqual(res.status_code, 200)

    def test_get_all_tenants(self):
        self.get_user = reverse("get-users")
        self.client.post(self.register_url, self.user_data)
        response = self.client.get(self.get_user)
        result = list(response)
        # pdb.set_trace()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][0]["entry"], "Tenant")
        self.assertIsInstance(result, list)

    def test_refresh_token(self):
        self.refreshToken = "/api/v1/refresh-token/"
        self.client.post(self.register_url, self.user_data)
        # pdb.set_trace()
        token = self.client.get(self.refreshToken + self.user_data["email"])
        self.assertEqual(token.status_code, 200)
        self.assertNotEqual(token.data, "check your email for verification")

    def test_verifyEmail_endpoint(self):
        self.email_verification_url = reverse("verify-email")
        self.client.post(self.register_url, self.user_data)
        # pdb.set_trace()
        token = self.client.get(self.email_verification_url)
        self.assertEqual(token.status_code, 400)
        self.assertEqual(token.data, "No token Input or Token already expired")

    def test_logout_endpoint(self):
        self.logout_url = reverse("logout")
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        self.client.post(self.login_url, self.user_data, format="json")
        logout_user = self.client.get(self.logout_url)
        self.assertEqual(logout_user.status_code, 200)

    def test_forgetPassword_endpoint(self):
        self.forgetPassword_url = "/api/v1/forget_password/"
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        password_reset = self.client.put(
            (self.forgetPassword_url + str(response.user_id)),
            self.forgetPassword_data,
        )
        self.assertEqual(password_reset.status_code, 200)
        self.assertNotEqual(password_reset.data, "password reset is successful")

    def test_get_and_delete_user_endpoint(self):
        self.getAndDeleteUser_url = "/api/v1/user/get/"
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        get_user = self.client.get((self.getAndDeleteUser_url + str(response.user_id)))
        delete_user = self.client.delete(
            (self.getAndDeleteUser_url + str(response.user_id))
        )
        self.assertEqual(get_user.status_code, 200)
        self.assertEqual(delete_user.status_code, 200)
        self.assertNotEqual(get_user.data["name"], "wreco")

    def test_get_and_delete_agent_endpoint(self):
        self.getAndDeleteAgent_url = "/api/v1/agent/get/"
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        get_user = self.client.get((self.getAndDeleteAgent_url + str(response.user_id)))
        delete_user = self.client.delete(
            (self.getAndDeleteAgent_url + str(response.user_id))
        )
        self.assertEqual(get_user.status_code, 200)
        self.assertNotEqual(delete_user.status_code, 204)
        self.assertEqual(get_user.data["name"], "string")


# python manage.py test
