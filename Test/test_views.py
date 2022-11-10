from Test.test_setup import TestSetUp
import pdb
from apartment.models import Apartment
from Authentication.models import User
from django.urls import reverse
import pdb, json

class TestViews(TestSetUp):
    def test_apartment_post(self):
        self.client.post(self.register_url, self.agent_data, format="json")
        response = User.objects.get(email=self.agent_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        res = self.client.post(
            self.post_apartment_url, 
            self.apartment_data, 
            format='json'
            )
        self.assertEqual(res.status_code, 201)


    def test_apartment_list(self):
        # agent data needs to be registered before an apartment could be created.
        self.client.post(self.register_url, self.agent_data, format="json")
        response = User.objects.get(email=self.agent_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        res = self.client.post(
            self.post_apartment_url, 
            self.apartment_data, 
            format='json'
            )
        list_apartments = self.client.get(self.list_apartment)
        self.assertEqual(list_apartments.status_code, 200)
        self.assertNotEqual(list_apartments.status_code, 201)
        self.assertEqual(Apartment.objects.count(), 1)



    def test_get_update_and_delete_apartmentByID(self):
        a = self.client.post(
            self.register_url, 
            self.agent_data, 
            format="json"
            )
        get_agent = User.objects.get(email=self.agent_data["email"])
        get_agent.is_verify = True
        get_agent.is_active = True
        get_agent.save()
        self.getApartment_url = "/api/v1/apartment/"
        response = self.client.post(
            self.post_apartment_url, self.apartment_data,
            format='json'
        )
        apartment_list = self.client.get(self.list_apartment)
        # the base url is concatenated with the 
        # user ID from the post function
        get_apartment = self.client.get(
            (
                self.getApartment_url + 
                str(apartment_list.data[0]["apartment_id"])
                )
        )
        update_apartment_url = self.client.put(
            (
                self.getApartment_url + 
                str(apartment_list.data[0]["apartment_id"])),
                self.apartment_update,
        )
        apartment_delete_url = self.client.delete(
            (
                self.getApartment_url + 
                str(apartment_list.data[0]["apartment_id"])
                )
        )
        self.assertEqual(get_apartment.status_code, 200)
        self.assertEqual(apartment_delete_url.status_code, 204)
        self.assertNotEqual(
            get_apartment.data["apartment details"]['agent'], 
            "wreco"
            )
        self.assertEqual(
            get_apartment.data['apartment details']["agent"], 
            "string"
            )
        self.assertEqual(
            apartment_delete_url.data, 
            "Apartment deleted successfully"
            )
        # pdb.set_trace()
        self.assertEqual(
            apartment_list.data[0]["apartment_id"], 
            get_apartment.data['apartment details']["apartment_id"]
        )
        self.assertNotEqual(
            get_apartment.data['apartment details']['descriptions'], 
            'A three bedroom flat'
        )
        self.assertEqual(
            get_apartment.data['apartment details']['descriptions'], 
            'Banger the bangoly'
        )
        self.assertEqual(
            update_apartment_url.data, 
            "Data update was successful"
            )



    def test_user_cannot_register_with_no_data(self):
            res = self.client.post(self.register_url)
            self.assertEqual(res.status_code, 400)



    def test_user_can_register(self):
        response = self.client.post(
            self.register_url, self.user_data, format="json"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.data['message'], 
            'Check your email for verification'
            )
        self.assertNotEqual(response.status_code, 400)



    def test_NotVerifiedUser_cannot_login(self):
        self.client.post(self.register_url, self.user_data, format="json")
        invalid_user_detail ={
            "email":"akin@gmail.com",
            "password":"werner@004"
        }
        response = self.client.post(
            self.login_url, 
            invalid_user_detail, 
            format="json"
            )
        self.assertEqual(response.status_code, 404)



    def test_VerifiedUser_login(self):
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_user = True
        response.save()
        res = self.client.post(self.login_url, self.login_data, format="json")
        # pdb.set_trace()
        self.assertEqual(res.status_code, 200)

        

    def test_get_all_tenants(self):
        self.get_user = reverse("get-users")
        self.client.post(self.register_url, self.user_data)
        response = self.client.get(self.get_user)
        result = list(response)
        result_one =  json.loads(result[0])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(result_one[0]["entry"], "Tenant")
        self.assertIsInstance(result, list)



    def test_get_all_tenants_error(self):
            self.get_user = reverse("get-users")
            self.client.post(self.register_url, self.agent_data)
            response = self.client.get(self.get_user)
            # pdb.set_trace()
            self.assertEqual(response.status_code, 204)
            self.assertEqual(
                response.data, 
                "No registered user in the database"
                )
            self.assertNotEqual(
                response.data, 
                "Get user data is successful"
            )
            self.assertNotEqual(response.status_code, 200)

            
    
    def test_get_all_agents(self):
            self.get_user = reverse("get-agents")
            self.client.post(self.register_url, self.agent_data)
            response = self.client.get(self.get_user)
            result = list(response)
            result_one =  json.loads(result[0])
            self.assertEqual(response.status_code, 200)
            self.assertNotEqual(result_one[0]["entry"], "Tenant")
            self.assertEqual(result_one[0]["entry"], "Agent")
            # pdb.set_trace()
            self.assertEqual(response.status_code, 200)
            self.assertNotEqual(
                response.data, 
                "No registered user in the database"
                )
            self.assertNotEqual(response.status_code, 204)



    def test_verifyEmailError_endpoint(self):
        self.email_verification_url = reverse("verify-email")
        self.client.post(self.register_url, self.user_data)
        # pdb.set_trace()
        token = self.client.get(self.email_verification_url)
        self.assertEqual(token.status_code, 400)
        self.assertEqual(
            token.data, 
            "No token Input or Token already expired"
            )
        


    def test_logout_endpoint(self):
        self.logout_url = reverse("logout")
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        login = self.client.post(
            self.login_url, 
            self.user_data, format="json"
            )
        auth_token= json.loads(login.content).get("Token")
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {auth_token}")
        logout_user = self.client.get(self.logout_url)
        self.assertEqual(logout_user.status_code, 200)




    def test_forgetPassword_endpoint(self):
        self.forgetPassword_url = reverse("forget-password")
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        password_reset = self.client.put(
            (self.forgetPassword_url),
            self.forgetPassword_data,
        )
        self.assertEqual(password_reset.status_code, 200)
        self.assertNotEqual(
            password_reset.data, "password reset is successful"
        )



    def test_get_and_delete_user_endpoint(self):
        self.getAndDeleteUser_url = "/api/v1/user/get/"
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        response.is_verify = True
        response.is_active = True
        response.save()
        login = self.client.post(self.login_url, self.user_data, format="json")
        auth_token= login.data['Token']
        header= {'Authorization':'Token '+ auth_token}
        get_user = self.client.get(
            (self.getAndDeleteUser_url + str(response.email)), headers=header
        )
        delete_user = self.client.delete(
            (self.getAndDeleteUser_url + str(response.email)), headers=header
        )
        self.assertEqual(get_user.status_code, 200)
        self.assertEqual(delete_user.status_code, 204)
        self.assertNotEqual(get_user.data["name"], "wreco")



    def test_get_and_delete_agent_endpoint(self):
        self.getAndDeleteAgent_url = "/api/v1/agent/get/"
        self.client.post(self.register_url, self.user_data, format="json")
        response = User.objects.get(email=self.user_data["email"])
        # pdb.set_trace()
        response.is_verify = True
        response.is_active = True
        response.save()
        login = self.client.post(
            self.login_url, self.user_data, format="json"
            )
        auth_token= login.data['Token']
        header= {'Authorization':'Token '+ auth_token}
        get_user = self.client.get(
            (self.getAndDeleteAgent_url + str(response.email)),
            headers=header
        )
        delete_user = self.client.delete(
            (self.getAndDeleteAgent_url + str(response.email)),
            headers=header
        )
        self.assertEqual(get_user.status_code, 200)
        self.assertNotEqual(delete_user.status_code, 204)
        self.assertEqual(get_user.data["name"], "string")

