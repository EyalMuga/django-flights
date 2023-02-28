from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator

# Create your models here.
class Flight(models.Model):
    flight_number = models.CharField(max_length=20, unique=True, primary_key=True)
    origin_country = models.CharField(max_length=50)
    origin_city = models.CharField(max_length=50)
    origin_airport_code = models.CharField(max_length=10)
    destination_country = models.CharField(max_length=50)
    destination_city = models.CharField(max_length=50)
    destination_airport_code = models.CharField(max_length=10)
    date_time_origin = models.DateTimeField()
    date_time_destination = models.DateTimeField()
    total_seats = models.IntegerField()
    seats_left = models.IntegerField([MinValueValidator(0), MaxValueValidator(total_seats)], default=total_seats)
    is_cancelled = models.BooleanField(default=False)
    price = models.DecimalField(max_digits=10, decimal_places=2)


class Order(models.Model):
    User.id = models.ForeignKey(User, on_delete=models.PROTECT)
    flight = models.ForeignKey(Flight, on_delete=models.PROTECT)
    num_seats = models.IntegerField()
    order_date = models.DateTimeField(auto_now_add=True)

    @property
    def total_price(self):
        return self.num_seats * self.flight.price



