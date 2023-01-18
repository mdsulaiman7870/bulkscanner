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

        elif User.objects.filter(email=email).exists():
            messages.info(
                request, "Email Taken. Try another Email Address", extra_tags="emailtaken")
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