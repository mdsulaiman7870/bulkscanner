from django.urls import path

from abuseipdb import views

urlpatterns = [
    path('ip_scanner', views.bulk_ip_scanner, name='abuseipdb_ip_scanner'),
    path('scan_single_ip', views.scan_single_ip, name='abuseipdb_scan_single_ip'),
    path('malicious_ips', views.abuseipdb_malicious_ips, name='abuseipdb_malicious_ips'),
    path('ip_details/<str:ip>', views.ip_details, name='abuseipdb_ip_details'),
    path('all_ips', views.allips, name='abuseipdb_allips'),
    path('delete_ip/<str:ip>', views.delete_ip, name='abuseipdb_delete_ip'),
    path('delete_from_all_ips/<str:ip>', views.delete_ip, name='abuseipdb_delete_from_allips'),

    path('search_malicious_ips', views.search_malicious_ips, name='search_malicious_ips'),
    path('search_all_ips', views.search_all_ips, name='search_all_ips'),



]