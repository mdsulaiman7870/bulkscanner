from django.shortcuts import render, redirect
from virustotal.models import hashes, failed_scanned_hash, ip_addresses, failed_scanned_ip
from dashboard.models import vt_apis, columns
import pandas
from django.contrib import messages
import ipaddress
import requests
from django.core.paginator import Paginator
from django.db.models import Q


def bulk_ip_scanner(request):

    if request.user.is_authenticated:

        ip_malicious_found = False
        ip_flag_for_run_another_scan = True

        if request.method == 'POST':

            apikey = request.POST['vt_api']
            column_name = request.POST['column_name']
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

                headers = {
                    'x-apikey': apikey,
                }

                for i in ip_add:
                    # check ip is private or not
                    try:

                        ipcheck = ipaddress.ip_address(i).is_private
                    except:
                        continue

                    if ipcheck is True:
                        pass
                    else:

                        if not ip_addresses.objects.filter(ip=i).exists() and not failed_scanned_ip.objects.filter(ip=i).exists():

                            response = requests.get(
                                'https://www.virustotal.com/api/v3/ip_addresses/%s' % i, headers=headers)

                            decodedResponse = response.json()

                            if not 'error' in response.json():

                                MaliciousCount = decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]

                                last_analysis_stats = decodedResponse.get("data").get(
                                    "attributes").get("last_analysis_stats")
                                total_votes = decodedResponse.get("data").get(
                                    "attributes").get("total_votes")
                                network = decodedResponse.get("data").get(
                                    "attributes").get("network")
                                country = decodedResponse.get("data").get(
                                    "attributes").get("country")
                                owner = decodedResponse.get("data").get(
                                    "attributes").get("as_owner")
                                regional_internet_registry = decodedResponse.get("data").get(
                                    "attributes").get("regional_internet_registry")

                                datafor_ip = ip_addresses(
                                    ip=i,
                                    count=MaliciousCount,
                                    total_votes=total_votes,
                                    network=network,
                                    last_analysis_stats=last_analysis_stats,
                                    country=country,
                                    owner=owner,
                                    regional_internet_registry=regional_internet_registry,

                                )

                                datafor_ip.save()

                                if MaliciousCount >= 1:
                                    ip_malicious_found = True

                            else:
                                erro_code = decodedResponse["error"]["code"]

                                if erro_code == "QuotaExceededError":
                                    messages.info(
                                        request, "Your daily limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                                    return render(request, 'virustotal/scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found': ip_malicious_found, 'ip_flag_for_run_another_scan': ip_flag_for_run_another_scan})

                                else:

                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_code + ": " + message

                                    datafor_ips = failed_scanned_ip(
                                        ip=i,
                                        error=error_message
                                    )

                                    datafor_ips.save()
                                    continue
                        else:
                            continue

                # display malicious and failed IPs only in the given log file(newly scanned old both) for display on scanned_result.html
                ip_scanned_result = []
                ip_failed_scanned_result = []

                for i in ip_add:
                    success_result = ip_addresses.objects.filter(
                        Q(count__gt=0) & Q(ip=i))

                    failed_result = failed_scanned_ip.objects.filter(ip=i)

                    if success_result.exists() or failed_result.exists():
                        ip_scanned_result += success_result.values(
                            'ip', 'last_analysis_stats', 'date_time')
                        ip_failed_scanned_result += failed_result.values(
                            'ip', 'error')

            return render(request, 'virustotal/scanned_result.html', {'ip_failed_scanned_result': ip_failed_scanned_result, 'ip_scanned_result': ip_scanned_result, 'ip_malicious_found': ip_malicious_found, 'ip_flag_for_run_another_scan': ip_flag_for_run_another_scan})

        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data,
                       'columns_data': columns_data}

            return render(request, "virustotal/ip_scanner.html", context)

    else:
        return redirect("login")


def vt_malicious_ips(request):

    if request.user.is_authenticated:

        queryset = ip_addresses.objects.filter(count__gt=0).all()
        show_entries = request.GET.get('show_entries')

        if show_entries:

            paginator = Paginator(queryset, show_entries)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_malicious_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'virustotal/malicious_ips.html', context)

        else:

            paginator = Paginator(queryset, 50)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

        context = {'all_malicious_ips': queryset,
                   'ips_count': ips_count}

        return render(request, 'virustotal/malicious_ips.html', context)

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
                return render(request, 'virustotal/ip_details.html', context)

            except Exception as e:
                location_info_flag = False
                messages.info(request, e)
                ip_details = ip_addresses.objects.all().filter(ip=ip)
                context = {'location_info_flag': location_info_flag,
                           'ip_details': ip_details}
                return render(request, 'virustotal/ip_details.html', context)

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

            return render(request, 'virustotal/all_ips.html', context)

        else:

            paginator = Paginator(queryset, 50)

            ips_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_ips': queryset,
                       'ips_count': ips_count}

            return render(request, 'virustotal/all_ips.html', context)

    else:
        return redirect("login")


def delete_ip(request, ip):

    if request.user.is_authenticated:

        if not ip_addresses.objects.filter(ip=ip).exists():
            messages.info(request, "IP " + ip +
                          " not found in the table", extra_tags="ip_not_found")
            return redirect("malicious_ips")

        else:

            path = request.get_full_path()
            malicious_path = "/virustotal/delete_ip/%s" % ip
            all_path = "/virustotal/delete_from_all_ips/%s" % ip

            if path == malicious_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(
                    ip=ip).delete()
                messages.info(request, "IP " + ip +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("malicious_ips")

            elif path == all_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(
                    ip=ip).delete()
                messages.info(request, "IP " + ip +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("allips")

    else:
        return redirect("login")


def vt_malicious_hashes(request):

    if request.user.is_authenticated:

        queryset = hashes.objects.filter(count__gt=0).all()

        show_entries = request.GET.get('show_entries')

        if show_entries:

            paginator = Paginator(queryset, show_entries)

            hashes_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_malicious_hashes': queryset,
                       'hashes_count': hashes_count}

            return render(request, 'virustotal/malicious_hashes.html', context)

        else:

            paginator = Paginator(queryset, 50)

            hashes_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            show_entries = request.GET.get('show_entries')

            context = {'all_malicious_hashes': queryset,
                       'hashes_count': hashes_count}

        return render(request, 'virustotal/malicious_hashes.html', context)

    else:
        return redirect("login")


def delete_hash(request, hash):

    if request.user.is_authenticated:

        if not hashes.objects.filter(hash=hash).exists():
            messages.info(request, "Hash " + hash +
                          " not found in the table", extra_tags="ip_not_found")
            return redirect("malicious_hashes")

        else:

            path = request.get_full_path()
            malicious_path = "/virustotal/delete_hash/%s" % hash
            all_path = "/virustotal/delete_from_all_hashes/%s" % hash

            if path == malicious_path:
                delete_from_hashes_table = hashes.objects.filter(
                    hash=hash).delete()
                messages.info(request, "Hash " + hash +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("malicious_hashes")

            elif path == all_path:
                delete_from_hashes_table = hashes.objects.filter(
                    hash=hash).delete()
                messages.info(request, "Hash " + hash +
                              " has been deleted", extra_tags="ip_deleted")
                return redirect("all_hashes")

    else:
        return redirect("login")


def hash_details(request, hash):

    if request.user.is_authenticated:

        if hashes.objects.filter(hash=hash).exists():

            hash_details = hashes.objects.all().filter(hash=hash)

            context = {'hash_details': hash_details}

        else:
            context = {'not_exist': hash}

        return render(request, 'virustotal/hash_details.html', context)

    else:
        return redirect("login")


def all_hashes(request):

    if request.user.is_authenticated:

        queryset = hashes.objects.all()
        show_entries = request.GET.get('show_entries')

        if show_entries:

            paginator = Paginator(queryset, show_entries)

            hash_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_hashes': queryset,
                       'hash_count': hash_count}

            return render(request, 'virustotal/all_hashes.html', context)

        else:

            paginator = Paginator(queryset, 50)

            hash_count = paginator.count

            page_number = request.GET.get('page')

            queryset = paginator.get_page(page_number)

            context = {'all_hashes': queryset,
                       'hash_count': hash_count}

            return render(request, 'virustotal/all_hashes.html', context)

    else:
        return redirect("login")


def hash_scanner(request):

    if request.user.is_authenticated:

        if request.method == "POST":
            hash_malicious_found = False
            hash_flag_for_run_another_scan = True

            apikey = request.POST['vt_api']
            column_name = request.POST['column_name']

            add_file = request.FILES.get('logfile')

            hash_csv = pandas.read_csv(add_file)

            if not column_name in hash_csv.columns:

                messages.error(
                    request, "Error: ", extra_tags="columnnotfound")
                return redirect("hash_scanner")

            else:
                hash = hash_csv[column_name].unique().tolist()

                # removing whitespaces(start and end)
                hash = [str(i).strip() for i in hash if not pandas.isnull(
                    i) and str(i).strip() != '']

                headers = {
                    'x-apikey': apikey,
                }

                for i in hash:

                    if not hashes.objects.filter(hash=i).exists() and not failed_scanned_hash.objects.filter(hash=i).exists():

                        response = requests.get(
                            'https://www.virustotal.com/api/v3/files/%s' % i, headers=headers)

                        decodedResponse = response.json()

                        if not 'error' in response.json():
                            MaliciousCount = decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]

                            last_analysis_stats = decodedResponse.get("data").get(
                                "attributes").get("last_analysis_stats")
                            total_votes = decodedResponse.get("data").get(
                                "attributes").get("total_votes")
                            signature_info = decodedResponse.get("data").get(
                                "attributes").get("signature_info")
                            meaningful_name = decodedResponse.get("data").get(
                                "attributes").get("meaningful_name")

                            datafor_hash = hashes(
                                hash=i,
                                count=MaliciousCount,
                                votes=total_votes,
                                signature_info=signature_info,
                                last_analysis_stats=last_analysis_stats,
                                meaningful_name=meaningful_name,

                            )

                            datafor_hash.save()

                            if MaliciousCount >= 1:
                                hash_malicious_found = True

                        else:
                            erro_code = decodedResponse["error"]["code"]

                            if erro_code == "QuotaExceededError":
                                messages.info(
                                    request, "Your daily or hourly limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                                return render(request, 'virustotal/scanned_result.html', {'hash_failed_scanned_result': hash_failed_scanned_result, 'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan': hash_flag_for_run_another_scan})

                            else:

                                message = decodedResponse["error"]["message"]
                                error_message = erro_code + ": " + message
                                datafor_hash = failed_scanned_hash(
                                    hash=hash,
                                    error=error_message
                                )

                                datafor_hash.save()
                                continue
                    else:
                        continue

                # display malicious and failed hashes only in the given log file(newly scanned old both) for display on scanned_result.html

                hash_scanned_result = []
                hash_failed_scanned_result = []

                for i in hash:
                    success_result = hashes.objects.filter(
                        Q(count__gt=0) & Q(hash=i))

                    failed_result = failed_scanned_hash.objects.filter(
                        hash=i)

                    if success_result.exists() or failed_result.exists():
                        hash_scanned_result += success_result.values(
                            'hash', 'last_analysis_stats', 'date_time')
                        hash_failed_scanned_result += failed_result.values(
                            'hash', 'error')

            return render(request, 'virustotal/scanned_result.html', {'hash_failed_scanned_result': hash_failed_scanned_result, 'hash_scanned_result': hash_scanned_result, 'hash_malicious_found': hash_malicious_found, 'hash_flag_for_run_another_scan': hash_flag_for_run_another_scan})

        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data,
                       'columns_data': columns_data}

            return render(request, "virustotal/hash_scanner.html", context)

    else:
        return redirect("login")


def search_malicious_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_ip_search_result = ip_addresses.objects.filter(
            count__gt=0, ip__contains=search_text)

        context = {'vt_ip_search_result': vt_ip_search_result,
                   'search_text': search_text}

        return render(request, "virustotal/malicious_ips.html", context)

    else:
        return redirect("login")


def search_all_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_ip_search_result = ip_addresses.objects.filter(
            ip__contains=search_text)

        context = {'vt_ip_search_result': vt_ip_search_result,
                   'search_text': search_text}

        return render(request, "virustotal/all_ips.html", context)

    else:
        return redirect("login")


def search_malicious_hashes(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_hash_search_result = hashes.objects.filter(
            count__gt=0, hash__contains=search_text)

        context = {'vt_hash_search_result': vt_hash_search_result,
                   'search_text': search_text}

        return render(request, "virustotal/malicious_hashes.html", context)

    else:
        return redirect("login")


def search_all_hashes(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_hash_search_result = hashes.objects.filter(
            hash__contains=search_text)

        context = {'vt_hash_search_result': vt_hash_search_result,
                   'search_text': search_text}

        return render(request, "virustotal/all_hashes.html", context)

    else:
        return redirect("login")
