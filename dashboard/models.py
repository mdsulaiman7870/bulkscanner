import datetime
from django.db import models

# Create your models here.
class vt_apis(models.Model):
    api = models.CharField(
        unique=True, max_length=100)
    email = models.CharField(max_length=50)
    full_name = models.CharField(max_length=50)

    def __str__(self):
        return self.api


class abuseipdb_apis(models.Model):
    api = models.CharField(
        unique=True, max_length=100)
    email = models.CharField(max_length=50)
    full_name = models.CharField(max_length=50)

    def __str__(self):
        return self.api

class columns(models.Model):

    column_name = models.CharField(
        max_length=150, unique=True)

    date_time = models.DateTimeField(default=datetime.datetime.now())