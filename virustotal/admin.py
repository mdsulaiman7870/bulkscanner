import imp
from django.contrib import admin
from virustotal.models import hashes, ip_addresses, failed_scanned_ip, failed_scanned_hash

admin.site.register(ip_addresses)
admin.site.register(failed_scanned_hash)
admin.site.register(hashes)
admin.site.register(failed_scanned_ip)




