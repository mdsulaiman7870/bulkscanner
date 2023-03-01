from django.db import models
import datetime


class ip_addresses(models.Model):
    ip = models.CharField(max_length=50, unique=True)
    network = models.CharField(max_length=100, null=True)
    count = models.IntegerField(null=True)
    last_analysis_stats = models.JSONField(null=True)
    total_votes = models.JSONField(null=True)
    date_time = models.DateTimeField(default=datetime.datetime.now())
    owner = models.CharField(null=True, max_length=100)
    country = models.CharField(null=True, max_length=100)
    regional_internet_registry = models.CharField(null=True, max_length=100)

    def __str__(self):
        return self.ip


class failed_scanned_ip(models.Model):
    ip = models.CharField(max_length=20, unique=True)
    error = models.TextField(null=True)

    def __str__(self):
        return self.ip


class hashes(models.Model):
    hash = models.TextField(unique=True)
    count = models.IntegerField(null=True)
    votes = models.JSONField(null=True)
    signature_info = models.JSONField(null=True)
    last_analysis_stats = models.JSONField(null=True)
    meaningful_name = models.JSONField(null=True)

    date_time = models.DateTimeField(default=datetime.datetime.now())

    def __str__(self):
        return self.hash


class failed_scanned_hash(models.Model):
    hash = models.TextField(unique=True)
    error = models.TextField(null=True)
    date_time = models.DateTimeField(default=datetime.datetime.now())

    def __str__(self):
        return self.hash
