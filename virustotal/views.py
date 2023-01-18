import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from virustotal.models import hashes, failed_scanned_hash, ip_addresses, failed_scanned_ip
from dashboard.models import vt_apis, columns
from django.contrib.auth.models import User
import pandas
from django.contrib import messages
import ipaddress
import requests
from django.core.paginator import Paginator


def bulk_ip_scanner(request):

    if request.user.is_authenticated:

        ip_malicious_found = False
        ip_scanned_result = []
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

                headers = {
                    'x-apikey': apikey,
                }

                for i in ip_add:
                    # check ip is private or not
                    ipcheck = ipaddress.ip_address(i).is_private

                    if ipcheck is True:
                        pass
                    else:
                        if not ip_addresses.objects.filter(ip=i).exists() and not failed_scanned_ip.objects.filter(ip=i).exists():

                            response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/%s' % i, headers=headers)

                            decodedResponse = response.json()

                            if not 'error' in response.json(): 

                                MaliciousCount = decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]

                                last_analysis_stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")
                                total_votes = decodedResponse.get("data").get("attributes").get("total_votes")
                                network = decodedResponse.get("data").get("attributes").get("network")
                                country = decodedResponse.get("data").get("attributes").get("country")
                                owner = decodedResponse.get("data").get("attributes").get("as_owner")
                                regional_internet_registry = decodedResponse.get("data").get("attributes").get("regional_internet_registry")

                                
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

                                if MaliciousCount >=1:
                                    ip_scanned_result.append(i)
                                    ip_malicious_found = True

                            else:
                                erro_code = decodedResponse["error"]["code"]

                                if erro_code == "QuotaExceededError":
                                    messages.info(request, "Your daily limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                                    return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found':ip_malicious_found, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })

                                elif erro_code == "UserNotActiveError":
                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_code +": " + message
                                    messages.info(request, error_message)
                                    return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found':ip_malicious_found, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })
                                
                                
                                elif erro_code=="WrongCredentialsError":
                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_code +": " + message
                                    messages.info(request, error_message)
                                    return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found':ip_malicious_found, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })
                                
                                elif erro_code == "NotFoundError":

                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_code +": " + message

                                    datafor_ip = failed_scanned_ip(
                                        ip=i,
                                        error=error_message
                                    )

                                    datafor_ip.save()

                                    return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })
                                    
                                else:

                                    message = decodedResponse["error"]["message"]
                                    error_message = erro_code +": " + message

                                    datafor_ips = failed_scanned_ip(
                                        hash=i,
                                        error=error_message
                                    )

                                    datafor_ips.save()
                                    continue

                        else:
                            continue

            return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found':ip_malicious_found, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })

        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data, 'columns_data': columns_data}

            return render(request, "virustotal/ip_scanner.html", context)

    else:
        return redirect("login")



def ip_check(request, ip_add):

    try:
        ip = ipaddress.ip_address(ip_add)

        if ip.is_private:
            messages.error(request, ip_add + " is a private IP.", extra_tags="private_ip")
            return redirect("ip_scanner")
        
        else:
            return ip_add

    except ValueError:
        # messages.error(request, f'{ip_add} is not a valid IP address')
        return redirect("ip_scanner")
    
def scan_single_ip(request):

    if request.user.is_authenticated:

        if request.method == 'POST':
            ip_scanned_result = []
            ip_malicious_found = False
            ip_flag_for_run_another_scan = True

            apikey = request.POST['vt_api']
            ip_address = request.POST['ip_address']

            headers = {
                    'x-apikey': apikey,
                }

            '''First, check for ip address validation and private'''
            ip_check(request, ip_address)
            
            if not ip_addresses.objects.filter(ip=ip_address).exists() and not failed_scanned_ip.objects.filter(ip=ip_address).exists():

                response = requests.get(
                    'https://www.virustotal.com/api/v3/ip_addresses/%s' % ip_address, headers=headers)

                decodedResponse = response.json()

                if not 'error' in response.json(): 
                    MaliciousCount = decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]

                    last_analysis_stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")
                    total_votes = decodedResponse.get("data").get("attributes").get("total_votes")
                    network = decodedResponse.get("data").get("attributes").get("network")
                    country = decodedResponse.get("data").get("attributes").get("country")
                    owner = decodedResponse.get("data").get("attributes").get("as_owner")
                    regional_internet_registry = decodedResponse.get("data").get("attributes").get("regional_internet_registry")
                    
                    datafor_ip = ip_addresses(
                        ip=ip_address,
                        count=MaliciousCount,
                        total_votes=total_votes,
                        network=network,
                        last_analysis_stats=last_analysis_stats,
                        country=country,
                        owner=owner,
                        regional_internet_registry=regional_internet_registry,
                                        
                    )

                    datafor_ip.save()

                    if MaliciousCount >=1:
                        ip_scanned_result.append(ip_address)
                        ip_malicious_found = True

                else:
                    erro_code = decodedResponse["error"]["code"]

                    if erro_code == "QuotaExceededError":
                        messages.info(request, "Your daily or hourly limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                        return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })

                    elif erro_code == "UserNotActiveError":
                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        
                        return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })
                    
                    elif erro_code=="WrongCredentialsError":
                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        
                        return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })
                    
                    elif erro_code == "NotFoundError":

                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")

                        datafor_ip = failed_scanned_ip(
                            ip=ip_address,
                            error=error_message
                        )

                        datafor_ip.save()

                        return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_flag_for_run_another_scan':ip_flag_for_run_another_scan })                     
                        
                    else:

                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        datafor_ip = failed_scanned_ip(
                            ip=ip_address,
                            error=error_message
                        )

                        datafor_ip.save()
            else:
                messages.info(request, "IP already already exists in the table.", extra_tags="ip_already_exists")
                return redirect("ip_scanner")

            return render(request, 'virustotal/ip_scanned_result.html', {'ip_scanned_result': ip_scanned_result, 'ip_malicious_found': ip_malicious_found})


        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data, 'columns_data': columns_data}

            return render(request, "virustotal/ip_scanner.html", context)
    
    else:
        return redirect("login")

def vt_malicious_ips(request):

    if request.user.is_authenticated:

        queryset = ip_addresses.objects.filter(count__gt=0).all()
        # hashes_count = ip_addresses.objects.filter(count__gt=0).count()
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

                location = requests.get("https://geolocation-db.com/json/%s" % ip)
                locationdecodedResponse = location.json()

                countryCode = locationdecodedResponse.get('country_code')
                CountryName = locationdecodedResponse.get('country_name')
                state = locationdecodedResponse.get('state')
                longitude = locationdecodedResponse.get('longitude')
                Latitude = locationdecodedResponse.get('latitude')
                city = locationdecodedResponse.get('city')
                postal = locationdecodedResponse.get('postal')

                ip_details = ip_addresses.objects.all().filter(ip=ip)        
                context = {'location_info_flag':location_info_flag, 'ip_details': ip_details, 'countryCode':countryCode, 'CountryName':CountryName, 'state':state, 'longitude':longitude, 'city':city, 'postal':postal, 'Latitude':Latitude}
                return render(request, 'virustotal/ip_details.html', context)

            except Exception as e:
                location_info_flag = False
                messages.info(request, e)
                ip_details = ip_addresses.objects.all().filter(ip=ip)        
                context = {'location_info_flag':location_info_flag, 'ip_details': ip_details}
                return render(request, 'virustotal/ip_details.html', context)
       
        else:
            context={'not_exist': ip}

    else:
        return redirect("login")
    
    
def allips(request):

    if request.user.is_authenticated:

        # search_query = request.POST['search_query']
        # custom_search_query = all_ips.objects.filter(
        #     ip__icontains=search_query)
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
            messages.info(request, "IP " + ip + " not found in the table", extra_tags="ip_not_found")
            return redirect("malicious_hashes")

        else:

            path = request.get_full_path()
            malicious_path = "/virustotal/delete_ip/%s" % ip
            all_path = "/virustotal/delete_from_all_ips/%s" % ip

            if path == malicious_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(ip=ip).delete()
                messages.info(request, "IP " + ip + " has been deleted", extra_tags="ip_deleted")
                return redirect("malicious_ips")

            elif path == all_path:
                delete_from_ip_addresses_table = ip_addresses.objects.filter(ip=ip).delete()
                messages.info(request, "IP " + ip + " has been deleted", extra_tags="ip_deleted")
                return redirect("allips")

    else:
        return redirect("login")

def scan_single_hash(request):

    if request.user.is_authenticated:

        if request.method == "POST":

            hash_scanned_result = []
            
            hash_malicious_found= False
            hash_flag_for_run_another_scan = True

            apikey = request.POST['vt_api']
            hash = request.POST['hash']

            headers = {
                    'x-apikey': apikey,
                }

            if not hashes.objects.filter(hash=hash).exists() and not failed_scanned_hash.objects.filter(hash=hash).exists():


                response = requests.get(
                        'https://www.virustotal.com/api/v3/files/%s' % hash, headers=headers)

                decodedResponse = response.json()

                if not 'error' in response.json(): 
                    MaliciousCount = decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"]

                    last_analysis_stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")
                    total_votes = decodedResponse.get("data").get("attributes").get("total_votes")
                    signature_info = decodedResponse.get("data").get("attributes").get("signature_info")
                    meaningful_name = decodedResponse.get("data").get("attributes").get("meaningful_name")

                    datafor_hash = hashes(
                        hash=hash,
                        count=MaliciousCount,
                        votes=total_votes,
                        signature_info=signature_info,
                        last_analysis_stats=last_analysis_stats,
                        meaningful_name = meaningful_name,
                                        
                    )

                    datafor_hash.save()

                    if MaliciousCount >=1:
                        hash_scanned_result.append(hash)
                        hash_malicious_found = True

                else:
                    erro_code = decodedResponse["error"]["code"]

                    if erro_code == "QuotaExceededError":
                        messages.info(request, "Your daily or hourly limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                        return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })

                    elif erro_code == "UserNotActiveError":
                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        
                        return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })
                    
                    elif erro_code=="WrongCredentialsError":
                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        
                        return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })
                    
                    elif erro_code == "NotFoundError":

                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")

                        datafor_hash = failed_scanned_hash(
                            hash=hash,
                            error=error_message
                        )

                        datafor_hash.save()
                        hash_scanned_result.append(hash)

                        return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })                     
                        
                    else:

                        message = decodedResponse["error"]["message"]
                        error_message = erro_code +": " + message
                        messages.info(request, error_message, extra_tags="error_message")
                        datafor_hash = failed_scanned_hash(
                            hash=hash,
                            error=error_message
                        )

                        datafor_hash.save()
                        hash_scanned_result.append(hash)

            else:
                messages.info(request, "Hash already already exists in the table.")
                return redirect("hash_scanner")    

            return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_malicious_found':hash_malicious_found, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan})

        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data, 'columns_data': columns_data}

            return render(request, "virustotal/hash_scanner.html", context)
    else:
        return redirect("login")
from django.http import JsonResponse


# def vt_hash_details(request, hash):

#     # apikey = request.POST['4ac7ac6a5465f2044168f0e1bf7feabad54d1a69cf600913cae560ca1cc09d2d']
#     apikey = "4ac7ac6a5465f2044168f0e1bf7feabad54d1a69cf600913cae560ca1cc09d2d"
#     headers = {
#             'x-apikey': apikey,
#         }            

#     response = requests.get(
#             'https://www.virustotal.com/api/v3/files/%s' % hash, headers=headers)

#     decodedResponse = response.json()

#     # return JsonResponse(decodedResponse, safe=False)
#     context = {'mydata':json.dumps(decodedResponse.get("data").get("attributes").get("meaningful_name"), indent=4)}
#     return render(request, "virustotal/hash_details.html", context)

def vt_malicious_hashes(request):

    if request.user.is_authenticated:

        queryset = hashes.objects.filter(count__gt=0).all()
        # hashes_count = hashes.objects.filter(count__gt=0).count()

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
            messages.info(request, "Hash " + hash + " not found in the table", extra_tags="ip_not_found")
            return redirect("malicious_hashes")

        else:

            path = request.get_full_path()
            malicious_path = "/virustotal/delete_hash/%s" % hash
            all_path = "/virustotal/delete_from_all_hashes/%s" % hash

            if path == malicious_path:
                delete_from_hashes_table = hashes.objects.filter(hash=hash).delete()
                messages.info(request, "Hash " + hash + " has been deleted", extra_tags="ip_deleted")
                return redirect("malicious_hashes")

            elif path == all_path:
                delete_from_hashes_table = hashes.objects.filter(hash=hash).delete()
                messages.info(request, "Hash " + hash + " has been deleted", extra_tags="ip_deleted")
                return redirect("all_hashes")

    else:
        return redirect("login")

def hash_details(request, hash):

    if request.user.is_authenticated:

        if hashes.objects.filter(hash=hash).exists():


            hash_details = hashes.objects.all().filter(hash=hash)
          

            context = {'hash_details': hash_details}
        
        else:
            context={'not_exist': hash}

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
            hash_scanned_result = []
            hash_malicious_found = False
            hash_flag_for_run_another_scan = True

            apikey = request.POST['vt_api']
            column_name = request.POST['column_name']
         
            add_file = request.FILES.get('logfile')

            hash_csv = pandas.read_csv(add_file)
        
            if not column_name in hash_csv.columns:

                messages.error(
                    request, "Error: Column name " + column_name + " doesn't exists in the given CSV hash file." , extra_tags="columnnotfound")
                return redirect("hash_scanner")

            else:
                hash = hash_csv[column_name].unique().tolist()

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

                            last_analysis_stats = decodedResponse.get("data").get("attributes").get("last_analysis_stats")
                            total_votes = decodedResponse.get("data").get("attributes").get("total_votes")
                            signature_info = decodedResponse.get("data").get("attributes").get("signature_info")
                            meaningful_name = decodedResponse.get("data").get("attributes").get("meaningful_name")
                            

                            datafor_hash = hashes(
                                hash=i,
                                count=MaliciousCount,
                                votes=total_votes,
                                signature_info=signature_info,
                                last_analysis_stats=last_analysis_stats,
                                meaningful_name = meaningful_name,
                                                
                            )

                            datafor_hash.save()

                            if MaliciousCount >=1:
                                hash_scanned_result.append(i)
                                hash_malicious_found = True

                        else:
                            erro_code = decodedResponse["error"]["code"]

                            if erro_code == "QuotaExceededError":
                                messages.info(request, "Your daily or hourly limit has been exceeded. Kindly Change your API Key and try again.", extra_tags='apilimit')
                                return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })

                            elif erro_code == "UserNotActiveError":
                                message = decodedResponse["error"]["message"]
                                error_message = erro_code +": " + message
                                messages.info(request, error_message, extra_tags="error_message")
                                
                                return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })
                            
                            elif erro_code=="WrongCredentialsError":
                                message = decodedResponse["error"]["message"]
                                error_message = erro_code +": " + message
                                messages.info(request, error_message, extra_tags="error_message")
                                
                                return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })
                            
                            elif erro_code == "NotFoundError":

                                message = decodedResponse["error"]["message"]
                                error_message = erro_code +": " + message

                                datafor_hash = failed_scanned_hash(
                                    hash=i,
                                    error=error_message
                                )

                                datafor_hash.save()
                                continue

                            else:

                                message = decodedResponse["error"]["message"]
                                error_message = erro_code +": " + message
                                messages.info(request, error_message, extra_tags="error_message")
                                datafor_hash = failed_scanned_hash(
                                    hash=hash,
                                    error=error_message
                                )

                                datafor_hash.save()
                                continue
                    else:
                        continue

            return render(request, 'virustotal/ip_scanned_result.html', {'hash_scanned_result': hash_scanned_result, 'hash_malicious_found':hash_malicious_found, 'hash_flag_for_run_another_scan':hash_flag_for_run_another_scan })
                
        else:
            vt_api_data = vt_apis.objects.all()
            columns_data = columns.objects.all()

            context = {'vt_api_data': vt_api_data, 'columns_data': columns_data}

            return render(request, "virustotal/hash_scanner.html", context)

    else:
        return redirect("login")

def search_malicious_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_ip_search_result = ip_addresses.objects.filter(count__gt=0, ip__contains=search_text)

        context = {'vt_ip_search_result': vt_ip_search_result, 'search_text':search_text}

        return render(request, "virustotal/malicious_ips.html", context)
        
    else:
        return redirect("login")

def search_all_ips(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_ip_search_result = ip_addresses.objects.filter(ip__contains=search_text)

        context = {'vt_ip_search_result': vt_ip_search_result, 'search_text':search_text}

        return render(request, "virustotal/all_ips.html", context)
        
    else:
        return redirect("login")

def search_malicious_hashes(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_hash_search_result = hashes.objects.filter(count__gt=0, hash__contains=search_text)

        context = {'vt_hash_search_result': vt_hash_search_result, 'search_text':search_text}

        return render(request, "virustotal/malicious_hashes.html", context)
        
    else:
        return redirect("login")

def search_all_hashes(request):

    if request.user.is_authenticated:

        search_text = request.GET['search_text']

        vt_hash_search_result = hashes.objects.filter(hash__contains=search_text)

        context = {'vt_hash_search_result': vt_hash_search_result, 'search_text':search_text}

        return render(request, "virustotal/all_hashes.html", context)
        
    else:
        return redirect("login")