"""flight_management URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from flight_app import views



urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/',TokenObtainPairView.as_view() , name='login'),
    path('auth/refresh-Token/', TokenRefreshView.as_view(), name='refresh-token'),
    path('flights/', views.FlightViewSet.as_view({'get': 'list'}), name='flights'),     
    path('flights/<int:pk>', views.FlightViewSet.as_view({'get': 'retrieve'}), name='flight'),
    path('flights/<int:pk>/update', views.FlightViewSet.as_view({'put': 'update'}), name='update_flight'),
    path('flights/<int:pk>/delete', views.FlightViewSet.as_view({'delete': 'destroy'}), name='delete_flight'),
    path('flights/create', views.FlightViewSet.as_view({'post': 'create'}), name='create_flight'),
    path('flights/<int:pk>/book', views.BookFlightView.as_view(), name='book_flight'),

]   

