from datetime import date, datetime, timedelta
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.models import User
from dashboard.models import vt_apis, abuseipdb_apis, columns
from virustotal.models import ip_addresses as vt_ip_addresses
from abuseipdb.models import ip_addresses as abuseipdb_ip_address
from virustotal.models import hashes as vt_hashes
from dashboard.models import vt_apis
from django.db.models import Count

def dashboard(request):
    if request.user.is_authenticated:

        # today = datetime.today()
     
        # day = today.day

        abuseipdb_malicious_ip_address = abuseipdb_ip_address.objects.filter().count()
        virustotal_malicious_ip_address = vt_ip_addresses.objects.filter().count()

        # abuseipdbchart = abuseipdb_ip_address.objects.all()

        context = {'abuseipdb_malicious_ip_address':abuseipdb_malicious_ip_address, 'virustotal_malicious_ip_address':virustotal_malicious_ip_address}

        return render(request, 'index.html', context)

    else:
        
        return redirect("login")

def vt_dashboard(request):

    if request.user.is_authenticated:

        vt_api_data = vt_apis.objects.values('api', 'full_name')

        virustotal_malicious_ip_address_count = vt_ip_addresses.objects.filter(count__gt=0).count()
        virustotal_malicious_hashes_count = vt_hashes.objects.filter(count__gt=0).count()

        top5_malicious_ip_addresses = vt_ip_addresses.objects.annotate(num_books=Count('ip')).filter(count__gt=0).order_by('-count')[:5]
        top5_malicious_hashes = vt_hashes.objects.annotate(num_books=Count('hash')).filter(count__gt=0).order_by('-count')[:5]

        last7days_malicious_ips = vt_ip_addresses.objects.filter(count__gt=0, date_time__gt=datetime.now()-timedelta(days=7))
        last7days_malicious_ips_count = vt_ip_addresses.objects.filter(count__gt=0, date_time__gt=datetime.now()-timedelta(days=7)).count()

        last7days_malicious_hashes = vt_hashes.objects.filter(count__gt=0, date_time__gt=datetime.now()-timedelta(days=7))
        # datetimefor_above = [data.date_time for data in last7days_malicious_hashes_datetime]
        last7days_malicious_hashes_datetime_count = last7days_malicious_hashes.count()

        context = {'last7days_malicious_hashes_datetime_count':last7days_malicious_hashes_datetime_count,'last7days_malicious_hashes':last7days_malicious_hashes,'vt_api_data':vt_api_data,'last7days_malicious_ips_count':last7days_malicious_ips_count,'last7days_malicious_ips':last7days_malicious_ips,'virustotal_malicious_ip_address_count':virustotal_malicious_ip_address_count, 'top5_malicious_ip_addresses':top5_malicious_ip_addresses, 'top5_malicious_hashes':top5_malicious_hashes, 'virustotal_malicious_hashes_count':virustotal_malicious_hashes_count}

        return render(request, 'virustotal-dashboard.html', context)

    else:
        return redirect("login")

def abuseipdb_dashboard(request):

    if request.user.is_authenticated:

        abuseipdb_api_data = abuseipdb_apis.objects.values('api', 'full_name')

        top5_malicious_ip_addresses = abuseipdb_ip_address.objects.annotate(num_books=Count('ip')).filter(abuseConfidenceScore__gt=0).order_by('-totalReports')[:5]
        
        top10_malicious_domains = abuseipdb_ip_address.objects.annotate(num_books=Count('ip')).filter(abuseConfidenceScore__gt=0).order_by('-totalReports')[:10]
        
        last7days_malicious_ips = abuseipdb_ip_address.objects.filter(abuseConfidenceScore__gt=0, date_time__gt=datetime.now()-timedelta(days=7))
        last7days_malicious_ips_count = abuseipdb_ip_address.objects.filter(abuseConfidenceScore__gt=0, date_time__gt=datetime.now()-timedelta(days=7)).count()

        abuseipdb_malicious_ip_address_count = abuseipdb_ip_address.objects.filter(abuseConfidenceScore__gt=0).count()

        context = {'top10_malicious_domains':top10_malicious_domains, 'abuseipdb_malicious_ip_address_count':abuseipdb_malicious_ip_address_count,'abuseipdb_api_data':abuseipdb_api_data, 'top5_malicious_ip_addresses':top5_malicious_ip_addresses, 'last7days_malicious_ips':last7days_malicious_ips, 'last7days_malicious_ips_count':last7days_malicious_ips_count}

        return render(request, 'abuseipdb-dashboard.html', context)

    else:
        return redirect("login")

def add_vt_api(request):

    if request.user.is_authenticated:

        if request.method == 'POST':

            api = request.POST["apikey"]
            email = request.POST["email"]
            full_name = request.POST["full_name"]

            if vt_apis.objects.filter(api=api).exists():

                messages.info(request, "API Already exists.", extra_tags="api_already_exists")
                return redirect("add_vt_api")

            else:
                api_data = vt_apis.objects.create(
                    api=api, email=email, full_name=full_name)

                api_data.save()
                messages.info(request, "API has been successfully added.", extra_tags="api_added")

                return redirect("add_vt_api")

        else:
            all_api_data = vt_apis.objects.all()
            context = {'all_api_data': all_api_data}

            return render(request, "dashboard/add_vt_api.html", context)
    else:
        return render(request, "login")

def add_abuseipdb_api(request):

    if request.user.is_authenticated:

        if request.method == 'POST':

            api = request.POST["apikey"]
            email = request.POST["email"]
            full_name = request.POST["full_name"]

            if abuseipdb_apis.objects.filter(api=api).exists():

                messages.info(request, "API Already exists.", extra_tags="api_already_exists")
                return redirect("add_abuseipdb_api")

            else:
                api_data = abuseipdb_apis.objects.create(
                    api=api, email=email, full_name=full_name)

                api_data.save()
                messages.info(request, "API has been successfully added.", extra_tags="api_added")

                return redirect("add_abuseipdb_api")

        else:
            all_api_data = abuseipdb_apis.objects.all()
            context = {'all_api_data': all_api_data}

            return render(request, "dashboard/add_abuseipdb_api.html", context)
    else:
        return render(request, "login")

def add_columns(request):

    if request.user.is_authenticated:

        if request.method == "POST":

            column_name = request.POST['column_name']

            if columns.objects.filter(column_name=column_name).exists():
                messages.info(
                    request, "Column Name already exists. Kindly check and try again.", extra_tags="column_already_exists")
                return redirect("add_columns")

            else:
                add_columns_data = columns.objects.create(
                    column_name=column_name)
                add_columns_data.save()
                messages.info(
                    request, "Column Name has been successfully added.", extra_tags="column_added")

                return redirect("add_columns")

        else:
            all_columns = columns.objects.all()
            context = {'all_columns': all_columns}

            return render(request, "dashboard/add_columns.html", context)
    else:
        return render(request, "login")

def custom_404(request, exception=None):
    return render(request, 'error-404.html', {'exception': exception})

def custom_500(request, exception=None):
    return render(request, 'error-500.html', {'exception': exception})

def delete_vt_api(request, id):

    if request.user.is_authenticated:

        if request.method == "POST":
            return redirect("index")

        else:

            if not vt_apis.objects.filter(id=id).exists():
                messages.info(request, "API not found in the table", extra_tags="api_not_found")
                return redirect("add_vt_api")

            else:

                delete_api = vt_apis.objects.filter(id=id).delete()
                messages.info(request, "API Key has been deleted", extra_tags="api_deleted")
                return redirect("add_vt_api")

    else:
        return render(request, "login")

def delete_abuseipdb_api(request, id):

    if request.user.is_authenticated:

        if request.method == "POST":
            return redirect("index")
            
        else:

            if not abuseipdb_apis.objects.filter(id=id).exists():
                messages.info(request, "API not found in the table", extra_tags="api_not_found")
                return redirect("add_abuseipdb_api")

            else:

                delete_api = abuseipdb_apis.objects.filter(id=id).delete()
                messages.info(request, "API Key has been deleted", extra_tags="api_deleted")
                return redirect("add_abuseipdb_api")

    else:
        return render(request, "login")

def delete_column(request, column_name):

    if request.user.is_authenticated:

        if request.method == "POST":
            return redirect("index")
            
        else:

            if not columns.objects.filter(column_name=column_name).exists():
                messages.info(request, "Column Name not found in the table", extra_tags="column_not_found")
                return redirect("add_columns")

            else:

                delete_column_name = columns.objects.filter(column_name=column_name).delete()
                messages.info(request, "Column Name has been deleted", extra_tags="column_deleted")
                return redirect("add_columns")

    else:
        return render(request, "login")
