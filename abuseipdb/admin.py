from django.contrib import admin
from abuseipdb.models import *

admin.site.register(ip_addresses)
admin.site.register(failed_scanned_ip)
