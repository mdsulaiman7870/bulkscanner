from django.urls import path

from . import views

urlpatterns = [
    path('ip_scanner', views.bulk_ip_scanner, name='ip_scanner'),
    path('scan_single_ip', views.scan_single_ip, name='scan_single_ip'),
    path('malicious_ips', views.vt_malicious_ips, name='malicious_ips'), 
    path('ip_details/<str:ip>', views.ip_details, name='ip_details'),
    path('delete_ip/<str:ip>', views.delete_ip, name='delete_ip'),
    path('delete_from_all_ips/<str:ip>', views.delete_ip, name='delete_from_allips'),
    path('all_ips', views.allips, name='allips'),

    #Hash Scanner URLs
    path('hash_scanner', views.hash_scanner, name='hash_scanner'),
    path('malicious_hashes', views.vt_malicious_hashes, name='malicious_hashes'),
    path('delete_hash/<str:hash>', views.delete_hash, name='delete_hash'),
    path('delete_from_all_hashes/<str:hash>', views.delete_hash, name='delete_from_all_hashes'),
    path('hash_details/<str:hash>', views.hash_details, name='hash_details'),
    path('all_hashes', views.all_hashes, name='all_hashes'),
    path('scan_single_hash', views.scan_single_hash, name='scan_single_hash'),
    # path('vt_hash_details/<str:hash>', views.vt_hash_details, name='vt_hash_details'),

    path('search_malicious_ips', views.search_malicious_ips, name='search_malicious_ips'),
    path('search_all_ips', views.search_all_ips, name='search_all_ips'),
    path('search_malicious_hashes', views.search_malicious_hashes, name='search_malicious_hashes'),
    path('search_all_hashes', views.search_all_hashes, name='search_all_hashes'),



]