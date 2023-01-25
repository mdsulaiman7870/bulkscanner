
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('virustotal/', include('virustotal.urls')),
    path('accounts/', include('accounts.urls')),
    path('abuseipdb/', include('abuseipdb.urls')),
    path('', include('dashboard.urls')),

]

handler404 = 'dashboard.views.custom_404'
handler500 = 'dashboard.views.custom_500'
