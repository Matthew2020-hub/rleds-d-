from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    def setUp(self):
        self.post_apartment_url = reverse("apartment-post")
        self.list_apartment = reverse("apartment-search")
        # self.get_apartment_url = reverse('get-apartment')

        self.apartment_data = {
            "apartment_title": "Korede Enterprise",
            "category": "Duplex",
            "price": "120k per year",
            "location": "Ajah",
            "agent": "wrecodde",
            "descriptions": "Banger the bangoly",
            "features": "3mfmfmvfivnfefnjvfgurnfn",
            "location_info": "3mfmfmvfivnfefnjvfgurnfn",
            "reviews": "3mfmfmvfivnfefnjvfgurnfn",
            "is_available": True,
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
            "reviews": "3mfmfmvfivnfefnjvfgurnfn",
            "is_available": True,
        }

        return super().setUp()

    def tearDown(self):
        return super().tearDown()
