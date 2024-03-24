from django.shortcuts import render, redirect,HttpResponse
from admin_datta.forms import RegistrationForm, LoginForm, UserPasswordChangeForm, UserPasswordResetForm, UserSetPasswordForm
from django.contrib.auth.views import LoginView, PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.views.generic import CreateView
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
import subprocess
import socket
import nmap
import requests
from .models import *

def index(request):

  context = {
    'segment'  : 'index',
    #'products' : Product.objects.all()
  }
  return render(request, "pages/index.html", context)
def home(request):

  context = {
    'segment'  : 'index',
    #'products' : Product.objects.all()
  }
  return render(request, "index.html", context)
def about(request):
    return render(request,"about.html")

def service(request):
    return render(request,"service.html")

def why(request):
    return render(request,"why.html")

def team(request):
    return render(request,"team.html")







# views.py

from urllib.parse import urlparse
import socket
import nmap
import requests
from requests.exceptions import RequestException
from django.conf import settings
@login_required
def basic_scan(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            # Validate URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL provided")

            # Retrieve IP address of the domain
            ip_address = socket.gethostbyname(parsed_url.netloc)

            # Scan for open ports using nmap
            nm = nmap.PortScanner()
            nm.scan(ip_address, arguments='-Pn -A -sV')  # Disable host discovery (-Pn)
            open_ports = []

            # Iterate over each open port and get service version details
            for port in nm[ip_address]['tcp']:
                port_info = {
                    'port': port,
                    'service': nm[ip_address]['tcp'][port]['name'],
                    'version': nm[ip_address]['tcp'][port]['version'],
                }
                open_ports.append(port_info)

            # Fetch subdomains from SecurityTrails API
            api_key = 'OZLp0391rI9y-tDO-niE3QKqF7Y0IZDn'
            api_url = f'https://api.securitytrails.com/v1/domain/{parsed_url.netloc}/subdomains'
            headers = {'APIKEY': api_key}
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()  # Raise exception for non-200 responses
            subdomains_data = response.json()

            # Extract subdomains from the response
            subdomains = subdomains_data.get('subdomains', [])

            # Prepare context to pass to template
            context = {
                'url': url,
                'ip_address': ip_address,
                'open_ports': open_ports,
                'subdomains': subdomains
            }
            return render(request, 'pages/scan_result.html', context)

        except (socket.error, nmap.PortScannerError, RequestException, ValueError) as e:
            error_message = f"An error occurred: {e}"
            return render(request, 'error.html', {'error_message': error_message})

    return render(request, 'pages/basic_scan.html')

# def website_scan(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
#         sql_injection_result, sql_injection_error = scan_for_sql_injection(url)
#         xss_result, xss_error = scan_for_xss(url)
#         # Pass the scan results to the template
#         return render(request, "pages/vuln_result.html", {'sql_injection_result': sql_injection_result, 'xss_result': xss_result})
#     return render(request, "pages/scan.html")

# def scan_for_sql_injection(url):
#     command = f"sqlmap -u {url} --batch"
#     process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     output, error = process.communicate()
#     return output.decode(), error.decode()

# def scan_for_xss(url):
#     command = f"XSStrike --url {url} --batch --silent"
#     process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     output, error = process.communicate()
#     return output.decode(), error.decode()

import subprocess

def website_scan(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        
        # Run Nikto to scan the URL
        nikto_output = subprocess.run(['nikto', '-h', url], capture_output=True, text=True)
        
        # Pass the Nikto output to the template
        return render(request, "pages/vuln_result.html", {'url': url, 'nikto_output': nikto_output.stdout})
    
    return render(request, "pages/scan.html")


# def run_nuclei_scan(url):
#     try:
#         # Run Nuclei scan for the given URL
#         scan_output = subprocess.check_output(['nuclei', '-target', url, '-t', 'path/to/templates'], text=True)
#         return scan_output
#     except subprocess.CalledProcessError as e:
#         # Handle errors if Nuclei scan fails
#         return f"Error running Nuclei scan: {e}"

# # Usage example in a Django view
# def website_scan(request):
#     if request.method == 'POST':
#         url = request.POST.get('url')
        
#         # Run Nuclei scan for the provided URL
#         nuclei_output = run_nuclei_scan(url)
        
#         # Pass the Nuclei output to the template for rendering
#         return render(request, "pages/vuln_result.html", {'nuclei_output': nuclei_output})

#     return render(request, "pages/scan.html")


@login_required
def subdomain_scan(request):
    if request.method == 'POST':
        try:
            url = request.POST.get('url')
            parsed_url = urlparse(url)
            api_key = 'OZLp0391rI9y-tDO-niE3QKqF7Y0IZDn'
            api_url = f'https://api.securitytrails.com/v1/domain/{parsed_url.netloc}/subdomains'
            headers = {'APIKEY': api_key}
            
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()  # Raise exception for non-200 responses
            subdomains_data = response.json()

            # Extract subdomains from the response
            subdomains = subdomains_data.get('subdomains', [])

            # Prepare context to pass to template
            context = {
                'url': url,
                'subdomains': subdomains
            }
            return render(request, 'pages/sub_result.html', context)

        except (socket.error, nmap.PortScannerError, RequestException, ValueError) as e:
            error_message = f"An error occurred: {e}"
            return render(request, 'error.html', {'error_message': error_message})

    return render(request, 'pages/sub_scan.html')