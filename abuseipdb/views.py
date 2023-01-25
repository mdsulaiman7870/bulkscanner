from textwrap import indent
from django.shortcuts import render, redirect
from django.contrib import messages
import ipaddress
import requests
# from dashboard.models import *
from dashboard.models import abuseipdb_apis, columns
from abuseipdb.models import ip_addresses, failed_scanned_ip
from django.core.paginator import Paginator
import pandas
from django.db.models import Q


def bulk_ip_scanner(request):

    if request.user.is_authenticated:

        if request.method == 'POST':

            ip_malicious_found = False
            ip_flag_for_run_another_scan = True

            apikey = request.POST['abuseipdb_api']
            column_name = request.POST['column_name']

            abuseipdbheaders = {'Accept': 'application/json',
                                'Key': apikey}
            abuseipdburl = 'https://api.abuseipdb.com/api/v2/check'

            # csv log file input

            add_file = request.FILES.get('logfile')

            ip_csv = pandas.read_csv(add_file)

            if not column_name in ip_csv.columns:

                messages.error(
                    request, "Error: ", extra_tags="columnnotfound")
                return redirect("ip_scanner")

            else:
                ip_add = ip_csv[column_name].unique().tolist()

                # removing whitespaces(start and end)
                ip_add = [str(i).strip() for i in ip_add if not pandas.isnull(
                    i) and str(i).strip() != '']

                for i in ip_add:

                    try:
                        # check ip is private or not
                        ipcheck = ipaddress.ip_address(i).is_private
                    except ValueError:
                        continue

                    if ipcheck is True:
                        pass

                    else:
                        if not ip_addresses.objects.filter(ip=i).exists() and not failed_scanned_ip.objects.filter(ip=i).exists():

                            querystring = {'ipAddress': i}

                            response = requests.request(
                                method='GET', url=abuseipdburl, headers=abuseipdbheaders, params=querystring)

                            decodedResponse = response.json()

                            if not 'error' in response.json():

                                isPublic = decodedResponse.get(
                                    "data").get("isPublic")
                                ipVersion = decodedResponse.get(
                                    "data").get("ipVersion")
                                isWhitelisted = decodedResponse.get(
                                    "data").get("isWhitelisted")
                                abuseConfidenceScore = decodedResponse.get(
                                    "data").get("abuseConfidenceScore")
                                countryCode = decodedResponse.get(
                                    "data").get("countryCode")
                                usageType = decodedResponse.get(
                                    "data").get("usageType")
                                isp = decodedResponse.get("data").get("isp")
                                domain = decodedResponse.get(
                                    "data").get("domain")
                                totalReports = decodedResponse.get(
                                    "data").get("totalReports")
                                numDistinctUsers = decodedResponse.get(
                                    "data").get("numDistinctUsers")
                                lastReportedAt = decodedResponse.get(
                                    "data").get("lastReportedAt")
                                hostnames = decodedResponse.get(
                                    "data").get("hostnames")

                                datafor_ip = ip_addresses(
                                    ip=i,
                                    isPublic=isPublic,
                                    ipVersion=ipVersion,
                                    isWhitelisted=isWhitelisted,
                                    abuseConfidenceScore=abuseConfidenceScore,
                                    countryCode=countryCode,
                                    usageType=usageType,
                                    isp=isp,
                                    domain=domain,
                                    totalReports=totalReports,
                                    numDistinctUsers=numDistinctUsers,
                                    lastReportedAt=lastReportedAt,
                                    hostnames=hostnames
                                )

                                datafor_ip.save()

                                if abuseConfidenceScore >= 1:
                                    ip_malicious_found = True

                            else:
                                erro_status = decodedResponse["error"]["status"]

                                if erro_status == 429:
                                    messages.info(
                                        request, "Your daily or hourly limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                                    return render(request, 'abuseipdb/scanned_result.html', {'ip_failed_sanned_result': ip_failed_sanned_result, 'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan': ip_flag_for_run_another_scan})

                                else:

                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_status + ": " + message
                                    messages.info(
                                        request, error_message, extra_tags="error_message")
                                    datafor_ip = failed_scanned_ip(
                                        ip=i,
                                        error=error_message
                                    )

                                    datafor_ip.save()
                                    continue

                        else:
                            pass

                # display malicious and failed IPs only in the given log file(newly scanned old both) for display on scanned_result.html
                ip_scanned_result = []
                ip_failed_sanned_result = []

                for i in ip_add:
                    success_result = ip_addresses.objects.filter(
                        (Q(abuseConfidenceScore__gt=0,) | Q(totalReports__gt=0)) & Q(ip=i))

                    failed_result = failed_scanned_ip.objects.filter(ip=i)

                    if success_result.exists() or failed_result.exists():
                        ip_scanned_result += success_result.values('ip',
                                                                   'abuseConfidenceScore', 'isWhitelisted', 'date_time')
                        ip_failed_sanned_result += failed_result.values(
                            'ip', 'error_message')

            return render(request, 'abuseipdb/scanned_result.html', {'ip_failed_sanned_result': ip_failed_sanned_result, 'ip_scanned_result': ip_scanned_result, 'ip_malicious_found': ip_malicious_found, 'ip_flag_for_run_another_scan': ip_flag_for_run_another_scan})

        else:
            abuseipdb_api_data = abuseipdb_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'abuseipdb_api_data': abuseipdb_api_data,
                       'columns_data': columns_data}

            return render(request, "abuseipdb/ip_scanner.html", context)

    else:
        return redirect("login")


def abuseipdb_malicious_ips(request):

    if request.user.is_authenticated:

        queryset = ip_addresses.objects.filter(
            Q(abuseConfidenceScore__gt=0) | Q(totalReports__gt=0)).all()
        show_entries = request.GET.get('show_entries')

        if show_entries:

            paginator = Paginator(queryset, show_entries)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_malicious_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'abuseipdb/malicious_ips.html', context)

        else:
            paginator = Paginator(queryset, 50)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_malicious_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'abuseipdb/malicious_ips.html', context)

    else:
        return redirect("login")


def ip_details(request, ip):

    if request.user.is_authenticated:

        if ip_addresses.objects.filter(ip=ip).exists():

            try:

                location_info_flag = True

                location = requests.get(
                    "https://geolocation-db.com/json/%s" % ip)
                locationdecodedResponse = location.json()

                countryCode = locationdecodedResponse.get('country_code')
                CountryName = locationdecodedResponse.get('country_name')
                state = locationdecodedResponse.get('state')
                longitude = locationdecodedResponse.get('longitude')
                Latitude = locationdecodedResponse.get('latitude')
                city = locationdecodedResponse.get('city')
                postal = locationdecodedResponse.get('postal')

                ip_details = ip_addresses.objects.all().filter(ip=ip)
                context = {'location_info_flag': location_info_flag, 'ip_details': ip_details, 'countryCode': countryCode,
                           'CountryName': CountryName, 'state': state, 'longitude': longitude, 'city': city, 'postal': postal, 'Latitude': Latitude}
                return render(request, 'abuseipdb/ip_details.html', context)

            except Exception as e:
                location_info_flag = False
                messages.info(request, e)
                ip_details = ip_addresses.objects.all().filter(ip=ip)
                context = {'location_info_flag': location_info_flag,
                           'ip_details': ip_details}
                return render(request, 'abuseipdb/ip_details.html', context)

        else:
            context = {'not_exist': ip}

    else:
        return redirect("login")


def allips(request):

    if request.user.is_authenticated:

        queryset = ip_addresses.objects.all()
        show_entries = request.GET.get('show_entries')

        if show_entries:

            paginator = Paginator(queryset, show_entries)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'abuseipdb/all_ips.html', context)

        else:

            paginator = Paginator(queryset, 50)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'abuseipdb/all_ips.html', context)

    else:
        return redirect("login")


def delete_ip(request, ip):

    if request.user.is_authenticated:

        if not ip_addresses.objects.filter(ip=ip).exists():
            messages.info(request, "IP " + ip +
                          " not found in the table", extra_tags="ip_not_found")
            return redirect("abuseipdb_allips")

        else:

            path = request.get_full_path()
            malicious_path = "/abuseipdb/delete_ip/%s" % ip
            all_path = "/abuseipdb/delete_from_all_ips/%s" % ip

            if path == malicious_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(
                    ip=ip).delete()
                messages.info(request, "IP " + ip +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("abuseipdb_malicious_ips")

            elif path == all_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(
                    ip=ip).delete()
                messages.info(request, "IP " + ip +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("abuseipdb_allips")

    else:
        return redirect("login")


def search_malicious_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        ip_search_result = ip_addresses.objects.filter(
            Q(abuseConfidenceScore__gt=0) | Q(totalReports__gt=0), ip__contains=search_text)

        context = {'ip_search_result': ip_search_result,
                   'search_text': search_text}

        return render(request, "abuseipdb/malicious_ips.html", context)

    else:
        return redirect("login")


def search_all_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        ip_search_result = ip_addresses.objects.filter(
            ip__contains=search_text).all()

        context = {'ip_search_result': ip_search_result,
                   'search_text': search_text}

        return render(request, "abuseipdb/all_ips.html", context)

    else:
        return redirect("login")
