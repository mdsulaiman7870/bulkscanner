from django.urls import path

from . import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('login/', views.login, name='login'),

    # path('login', views.login, name='login'),
    path('reset_password', views.reset_password, name='reset_password'),
    path('logout', views.logout, name='logout'),
    path('user_profile', views.update_userProfile, name='user_profile'),
    path('update_password', views.update_password, name='update_password'),
    # path('register', views.register, name='register'),

]
