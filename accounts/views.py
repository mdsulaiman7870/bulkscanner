from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User, auth


def register(request):
    if request.user.is_authenticated:
        messages.info(request,
                      "You are already registered. Log out first then try to register for another account.")
        return redirect("index")

    if request.method == 'POST':
        first_name = request.POST['firstname']
        last_name = request.POST['lastname']
        username = request.POST['username']
        email = request.POST['email']

        password = request.POST['password']

        if User.objects.filter(username=username).exists():
            messages.info(
                request, "Username Taken. Try another Username", extra_tags="usernametaken")
            return redirect("register")

        else:
            user = User.objects.create_user(
                username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            user.save()

            messages.info(
                request, "You are succesfully registered. Login to continue", extra_tags='register')
            return redirect("login")
    else:
        return render(request, 'accounts/sign-up.html')


def login(request):

    if request.user.is_authenticated:
        return redirect("index")

    if request.method == 'POST':
        username = request.POST["username"]
        password = request.POST["password"]

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect("index")
        else:
            messages.info(request, "Invalid Credentials", extra_tags='login')
            return redirect("login")
    else:
        return render(request, "accounts/sign-in.html")


def logout(request):

    if request.user.is_authenticated:
        auth.logout(request)
        return redirect("login")

    else:
        messages.info(request, "You are already logged out.",
                      extra_tags='logout')
        return redirect("login")


def reset_password(request):

    if request.method == 'POST':

        email = request.POST['email']
        password = request.POST["password"]

        if User.objects.filter(email=email).exists():

            u = User.objects.get(email=email)
            u.set_password(password)
            u.save()
            messages.info(request, "Password has been reset. Please Login below",
                          extra_tags="resetdone")
            return redirect('login')

        else:
            messages.error(
                request, "Email doesn't exists in database", extra_tags="emailnotpresent")
            return redirect("reset_password")

    else:
        return render(request, "accounts/forgot-password.html")


def update_userProfile(request):

    if request.user.is_authenticated:

        if request.method == 'POST':
            email = request.POST['email']
            first_name = request.POST['firstname']
            last_name = request.POST['lastname']

            User.objects.filter(id=request.user.id).update(
                email=email, first_name=first_name, last_name=last_name)
            messages.info(
                request, "User information has been updated.", extra_tags="updated")
            # return render(request, 'accounts/user-profile.html')
            return redirect('user_profile')

        else:
            user_id = request.user.id
            first_name = request.user.first_name
            last_name = request.user.last_name
            email = request.user.email
            date_joined = request.user.date_joined
            username = request.user.username

            context = {
                'user_id': user_id,
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'username': username,
                'date_joined': date_joined,
            }
            return render(request, 'accounts/user-profile.html', context=context)
    else:
        messages.info(request, "Please login first to change the user profile information.",
                      extra_tags='update_userProfile')
        return redirect("login")


def update_password(request):

    if request.user.is_authenticated:

        if request.method == 'POST':

            current_password = request.POST['current_password']
            new_password = request.POST['new_password']
            confirm_password = request.POST['confirm_password']

            user = request.user

            if new_password != confirm_password:
                messages.info(
                    request, "Passwords doesn't match. Please try again.", extra_tags="password_not_matched")
                return redirect('user_profile')

            elif user.check_password(current_password) is False:
                messages.info(
                    request, "Your current password is invalid. Reset your password if forgotten.", extra_tags="invalid_password")
                return redirect('user_profile')

            else:
                user.set_password(new_password)
                user.save()
                messages.info(
                    request, "Passwords has been updated. Please login again.", extra_tags="password_updated")
                return redirect('user_profile')

        else:
            return render(request, "accounts/user-profile.html")

    else:
        messages.info(request, "Please login first to update the password.",
                      extra_tags="not_logged_in_pass_update")
        return redirect("login")
