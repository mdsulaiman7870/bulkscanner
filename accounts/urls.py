from django.urls import path

from . import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('login/', views.login, name='login'),

    # path('login', views.login, name='login'),
    path('reset_password', views.reset_password, name='reset_password'),
    path('logout', views.logout, name='logout'),


    # path('register', views.register, name='register'),

]