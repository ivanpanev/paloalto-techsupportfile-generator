import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import requests
import getpass
import re
import time
import sys
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global progress storage and lock
progress_data = {}
lock = Lock()

def get_api_key(username, password, palo_ip):
    print('Attempting to retrieve API key from:', palo_ip)
    url = f'https://{palo_ip}/api'
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    try:
        response = requests.get(url, params=params, verify=False)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            api_key_element = root.find('.//key')
            if api_key_element is not None:
                return api_key_element.text
            else:
                print(f"No API key found in the response from {palo_ip}. Check credentials and firewall access.")
        else:
            print("Failed to retrieve API Key. Status code:", response.status_code, "Response:", response.text)
    except Exception as e:
        print(f"Error communicating with {palo_ip}: {e}")
    return None

def get_palo_alto_system_info(palo_ip, api_key):
    api_url = f'https://{palo_ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={api_key}'
    try:
        response = requests.get(api_url, verify=False)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        root = ET.fromstring(response.content)
        hostname = root.find('.//hostname').text
        return hostname
    except Exception as e:
        print(f"Error retrieving system info from {palo_ip}: {e}")
        return None

def initiate_tech_support(palo_ip, hostname, api_key):
    print('Requesting tech support file from:', hostname)
    url = f'https://{palo_ip}/api/?type=export&category=tech-support'
    params = {'key': api_key}
    try:
        response = requests.get(url, params=params, verify=False)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            job_element = root.find('.//job')
            if job_element is not None:
                return job_element.text
            else:
                print(f"No job ID found in response from {palo_ip}. Response may not be as expected.")
        else:
            print("Failed to initiate tech support. Status:", response.status_code, "Response:", response.text)
    except Exception as e:
        print(f"Error starting tech support job on {palo_ip}: {e}")
    return None

def print_progress_bar(percentage):
    # Define the width of the progress bar (e.g., 30 characters wide)
    bar_width = 50
    filled_length = int(bar_width * percentage // 100)
    bar = '█' * filled_length + '-' * (bar_width - filled_length)
    sys.stdout.write(f'\rProgress |{bar}| {percentage}% Complete')
    sys.stdout.flush()

def update_progress(job_id, progress):
    global progress_data
    with lock:
        progress_data[job_id] = progress
        average_progress = sum(progress_data.values()) / len(progress_data)
    print_progress_bar(average_progress)

def check_job_status(palo_ip, hostname, api_key, job_id):
    print(f'Starting job status check for {hostname}')
    try:
        while True:
            response = requests.get(f'https://{palo_ip}/api/', params={'key': api_key, 'type': 'export', 'category': 'tech-support', 'action': 'status', 'job-id': job_id}, verify=False)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                status_element = root.find('.//status')
                if status_element is not None:
                    status = status_element.text
                    if status == "FIN":
                        resultfile_element = root.find('.//resultfile')
                        if resultfile_element is not None:
                            #print(f"\n{hostname}: Job complete, ready to download file...") #Supressing informative print statemenets in favor of fancy progress bar display. 
                            return job_id, resultfile_element.text  # Return both job ID and file path
                        else:
                            print(f"\n{hostname}: Job finished but no file path found.")
                            return job_id, None
                    if root.find('.//progress') is not None:
                        try:
                            progress = int(root.find('.//progress').text)
                            update_progress(job_id, progress)
                        except ValueError:
                            print(f"Waiting for job to complete. Current status: {status}")
                else:
                    print(f"\n{hostname}: Malformed response or missing data")
                    break
            else:
                print(f"\n{hostname}: Failed to check job status, Status: {response.status_code}")
            time.sleep(10)
    except Exception as e:
        print(f"\n{hostname}: Error checking job status, Exception: {e}")

def download_file(palo_ip, api_key, job_id, hostname, formatted_datetime):
    filename = f"{hostname}_techsupport_{formatted_datetime}.tgz" if hostname else "techsupport.tgz"
    #print(f'Downloading file: {filename} from:', palo_ip) #Supressing informative print statemenets in favor of fancy progress bar display. 
    url = f'https://{palo_ip}/api/?key={api_key}&type=export&category=tech-support&action=get&job-id={job_id}'
    try:
        response = requests.get(url, params={'key': api_key}, verify=False, stream=True)
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        #print(f"File downloaded: {filename}") #Supressing informative print statemenets in favor of fancy progress bar display. 
    except Exception as e:
        print(f"Error downloading file {filename} from {palo_ip}: {e}")

def generate_tech_support_file(palo_ip, username, password, formatted_datetime):
    api_key = get_api_key(username, password, palo_ip)
    if api_key:
        hostname = get_palo_alto_system_info(palo_ip, api_key)
        job_id = initiate_tech_support(palo_ip, hostname, api_key)
        if job_id:
            job_id, file_path = check_job_status(palo_ip, hostname, api_key, job_id)
            if file_path:
                download_file(palo_ip, api_key, job_id, hostname, formatted_datetime)

if __name__ == "__main__":
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    firewalls = []
    current_datetime = datetime.now()
    year_short = current_datetime.strftime("%Y")[2:]
    formatted_datetime = current_datetime.strftime(f"%d%m{year_short}_%H%M%S")
    
    print("Enter firewall IPs. Type 'end' or 'done' to finish.")
    while True:
        user_input = input()
        if user_input.lower() in ['done', 'end']:
            break
        # Regular expression pattern for IPv4 address
        ipv4_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ipv4_pattern, user_input):
            firewalls.append(user_input)
        else:
            print("Invalid IPv4 address. Please enter a valid IPv4 address.")

    with ThreadPoolExecutor(max_workers=len(firewalls)) as executor:
        for ip in firewalls:
            executor.submit(generate_tech_support_file, ip, username, password, formatted_datetime)
    
    print_progress_bar(100)