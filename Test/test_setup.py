from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    def setUp(self):
        self.post_apartment_url = reverse("apartment-post")
        self.list_apartment = reverse("apartment-list")
        self.register_url = reverse("user-register")
        self.login_url = reverse("signin")


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

        # self.get_apartment_url = reverse('get-apartment')

        self.apartment_data = {
            "apartment_title": "Korede Enterprise",
            "category": "Duplex",
            "price": "120k per year",
            "location": "Ajah",
            "agent": "string",
            "image_url":{
                'https://res.cloudinary.com/housefree/image/upload/v1/media/apartment/am_oma6vv',
                'https://res.cloudinary.com/housefree/image/upload/v1/media/apartment/am_om'
                },
            
            "descriptions": "Banger the bangoly",
            "features": "3mfmfmvfivnfefnjvfgurnfn",
            "location_info": "3mfmfmvfivnfefnjvfgurnfn",
            "is_available": True
        }
        self.apartment_update = {
            "apartment_title": "Korede Enterprise",
            "category": "Duplex",
            "price": "125k per year",
            "location": "Ajah",
            "agent": "wrecodde",
            "descriptions": "4 bedroom detached",
            "features": "3mfmfmvfivnfefnjvfgurnfn",
            "location_info": "3mfmfmvfivnfefnjvfgurnfn",
            "is_available": True
        }
        self.reviews_create = {
           "reviews": [
               "a light bulb", "a green pea and a nice culcumin aspicera"
               ] 
        }
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
