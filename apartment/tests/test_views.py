from django.urls import reverse
import json
from .test_setup import TestSetUp
import pdb
from ..models import Apartment


class TestViews(TestSetUp):
    def test_post_apartment(self):
        res = self.client.post(self.post_apartment_url, self.apartment_data)
        self.assertEqual(res.status_code, 201)

    # def test_apartment_list(self):
    #     self.apartment = {
    #         "location": "Ajah",
    #         "price_range": "120k per year",
    #         "category": "Duplex"
    #     }
    #     post = self.client.post(self.post_apartment_url, self.apartment_data)
    #     list_apartments = self.client.get(self.list_apartment, self.apartment)
    #     # pdb.set_trace()
    #     self.assertEqual(list_apartments.status_code, 200)
    #     self.assertEqual(Apartment.objects.count(), 1)

    def test_get_apartmentByID(self):
        self.getApartment_url = "/api/v1/apartment/"
        response = self.client.post(
            self.post_apartment_url, self.apartment_data
        )
        get_apartments = Apartment.objects.get(
            apartment_id=response.data["apartment_id"]
        )
        # delete_apartment.destroy()
        # the base url is concatenated with the user ID from the post function
        get_apartment = self.client.get(
            (self.getApartment_url + str(response.data["apartment_id"]))
        )
        update_apartment = self.client.put(
            (self.getApartment_url + str(response.data["apartment_id"])),
            self.apartment_update,
        )
        apartment_updated = Apartment.objects.get(
            apartment_id=response.data["apartment_id"]
        )

        self.assertEqual(get_apartment.status_code, 200)
        self.assertEqual(Apartment.objects.count(), 1)
        self.assertNotEqual(get_apartment.data["agent"], "wreco")
        pdb.set_trace()
        self.assertEqual(
            response.data["apartment_id"], get_apartment.data["apartment_id"]
        )
        self.assertNotEqual(
            get_apartments.descriptions, apartment_updated.descriptions
        )
        self.assertEqual(update_apartment.data, "Data update was successful")
        delete_apartment = self.client.delete(
            (self.getApartment_url + str(response.data["apartment_id"]))
        )
        self.assertEqual(delete_apartment.status_code, 204)
