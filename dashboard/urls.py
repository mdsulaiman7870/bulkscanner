from django.urls import path

from . import views

urlpatterns = [

    path('', views.dashboard, name='index'),
    path('add_vt_api', views.add_vt_api, name='add_vt_api'),
    path('add_abuseipdb_api', views.add_abuseipdb_api, name='add_abuseipdb_api'),
    path('add_columns', views.add_columns, name='add_columns'),

    path('vt_dashboard', views.vt_dashboard, name='vt_dashboard'),
    path('abuseipdb_dashboard', views.abuseipdb_dashboard, name='abuseipdb_dashboard'),

    path('delete_vt_api/<int:id>', views.delete_vt_api, name='delete_vt_api'),
    path('delete_abuseipdb_api/<int:id>', views.delete_abuseipdb_api, name='delete_abuseipdb_api'),

    path('delete_column/<str:column_name>', views.delete_column, name='delete_column'),

]

