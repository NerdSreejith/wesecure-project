from django.urls import path
from django.contrib.auth import views as auth_views

from . import views

urlpatterns = [
  path('dashboard/'       , views.index,  name='dash'),
  path(''       , views.home,  name='home'),
  path('basic-scan/', views.basic_scan, name='basic_scan'),
  path('vuln-scan/',views.website_scan,name="scan"),
  path('subdomains/',views.subdomain_scan,name="subdomain_scan"),
  path('about/',views.about,name="about"),
  path('service/',views.service,name="service"),
  path('team/',views.team,name="team"),
  path('why/',views.why,name="why"),
  

]
