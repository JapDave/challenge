from django.contrib import admin
from django.urls import path, include
from django.urls import path, re_path
from rest_framework import permissions
from .api import api

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', api.urls),
    path('transaction/', include('transaction.urls', namespace='transaction'))
]
