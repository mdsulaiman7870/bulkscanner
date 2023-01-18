from distutils.log import error
from enum import unique
from django.db import models
import datetime

class ip_addresses(models.Model):
    ip = models.CharField(max_length=20, unique=True)
    isPublic = models.CharField(max_length=10)
    ipVersion = models.IntegerField(null=True)
    isWhitelisted = models.BooleanField()
    abuseConfidenceScore = models.IntegerField(null=True)
    countryCode = models.CharField(null=True, max_length=5)
    usageType = models.TextField(null=True)
    isp = models.TextField(null=True)
    domain = models.TextField(null=True)
    totalReports = models.IntegerField(null=True)
    numDistinctUsers = models.IntegerField(null=True)
    lastReportedAt = models.DateTimeField()
    hostnames = models.JSONField(null=True)
    date_time = models.DateTimeField(default=datetime.datetime.now())
  
    def __str__(self):
            return self.ip

class failed_scanned_ip(models.Model):
    ip = models.CharField(max_length=20, unique=True)
    error_message = models.TextField(null=True)

    def __str__(self):
        return self.ip