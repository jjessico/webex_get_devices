"""
This script logs into a Webex Integration to get an access token
and uses that token to retrieve Webex device info
"""
import logging
import sys
import re
import json
from configparser import ConfigParser
import requests
import urllib3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def read_credentials():
    """
    Read the information required to login to a Webex Control Hub Integration from a flat
    configuration file. This includes: user, pass, client_id, client_secret, redirect_url,
    scope, and the oauth_url
    """
    parser = ConfigParser(interpolation=None)
    config_section = 'webex'
    config_path = r'..\\..\\restricted\webex.ini'
    try:
        parser.read(config_path)
    except Exception as error:
        logging.error('Cannot read config from %s',config_path)
        sys.exit('Unable to read credential file')

    #Read each portion of the configuration file into a variable
    if parser.has_section(config_section):
        config_params = parser.items(config_section)
        username = config_params[0][1]
        password = config_params[1][1]
        client_id = config_params[2][1]
        client_secret = config_params[3][1]
        redirect_url = config_params[4][1]
        scope = config_params[5][1]
        oauth_url = config_params[6][1]
        adp_proxies = config_params[7][1]
    else:
        logging.error('Cannot read section %s',config_section)
        sys.exit('No webex section of config file')

    #Return all the variables
    logging.info('Config read from section %s in file %s',config_section, config_path)
    return username, password, client_id, client_secret, redirect_url, scope, oauth_url, adp_proxies

def selenium_action(url, username, password):
    """
    Go to the oauth URL for a webex integration with Selenium. Emulate a user by entering
    username, clicking, password, clicking.  If you are on a host that will not intercept
    failed outbound HTTP requests with a friendly 200OK page, the selenium driver will except.
    The exception is caught and the attempted redirect URL is pulled out.  If you are on a
    host that will intercept failed HTTP with a friendly page (iBoss, state sponsored proxy, etc)
    selenium will not except.  In this case the chrome driver's performance log is mined for
    outbound HTTP requests that have the redirect URL in the base.

    In either case the URL is sent to another function to parse it for only the code. This
    code is then returned.
    """
    selenium_options = Options()
    caps = DesiredCapabilities.CHROME
    caps['goog:loggingPrefs'] = {'performance': 'ALL'}

    #Change to True to run headless
    selenium_options.headless = False
    driver = webdriver.Chrome(options=selenium_options, desired_capabilities=caps)
    driver.get(url)

    """
    Webdrive wait is used to make sure the page is fully loaded with the required
    elements before an action is taken
    """
    try:
        email_input = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, 'IDToken1'))
        )
    except:
        logging.error("Unable to find email box on login page")
        driver.quit()
        sys.exit()

    #Put in an e-mail address and press submit
    email_input.send_keys(username)
    email_submit = driver.find_element(By.ID, 'IDButton2')
    email_submit.click()


    try:
        password_input = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, 'IDToken2'))
        )
    except:
        logging.error("Unable to find password box on login page")
        driver.quit()
        sys.exit()

    #Put in a password
    password_input.send_keys(password)

    """
    Submit with the password button and then based on what happens with the browser session
    (except or OK) extract the code in a different way
    """
    try:
        password_submit = driver.find_element(By.ID, 'Button1')
        password_submit.click()
        chrome_log = driver.get_log('performance')
        code = extract_code(chrome_log)
        driver.quit()
        logging.info('Returning integration code without exception handling')
        return code
    except Exception as selenium_failure:
        redirect_error = selenium_failure.msg
        code = parse_redirect(redirect_error)
        driver.quit()
        logging.info('Returning integration code through exception handling')
        return code


def extract_code(chrome_log):
    """
    Look through every messge in the Chrome performance log.  For any message that indicates
    an outbound request, look for a line that will contain a code.  Then extract the code from that
    full URL with a regex.
    """
    for entry in chrome_log:
        log_message = entry['message']
        log_message_dict = json.loads(log_message)
        if log_message_dict['message']['method'] == 'Network.requestWillBeSent':
            requested_url = log_message_dict['message']['params']['documentURL']
            found_code = re.match(r'(^.*code=)(.*)(&state.*)', requested_url)
            if found_code is None:
                pass
            else:
                break

    return found_code[2]

def parse_redirect(error_message):
    """
    From a Selenium page load error message extract the code, which is everything
    between the code= and &state text in the URL that fails to resolve
    """
    match = re.match(r'(^.*code%3D)(.*)(%26state.*)', error_message)
    return match[2]

def get_access_token(method, url, headers, payload, proxy_dict):
    """
    Make an HTTP request with a specified METHOD to a desired URL with given
    headers.  Return the page contents as a BS4 object if the response is a 200
    """
    logging.info('url: %s', url)
    logging.info('headers: %s', headers)

    session = requests.Session()
    session.trust_env = True
    session.verify = False
    session.proxies = proxy_dict

    request = requests.Request(method, url, headers=headers, data=payload)
    prepped = request.prepare()

    try:
        response = session.send(prepped)
    except Exception as error:
        logging.error('A problem has occured connecting to the URL %s',url)
        logging.error(error)
        sys.exit()

    if response.status_code == 200:
        logging.info('Request status_code: %s', response.status_code)
        data = response.json()
        return data
    else:
        logging.error('Response Error - status_code: %s url: %s', response.status_code, url)
        sys.exit()

    return False

def get_devices(access_token, proxy_dict):
    """
    Use the access token to make a requests for all webex devices
    """
    session = requests.Session()
    session.trust_env = True
    session.verify = False
    session.proxies = proxy_dict
    method = 'GET'
    url = 'https://webexapis.com/v1/devices'
    headers = {
        'Authorization': 'Bearer '+access_token
    }
    request = requests.Request(method, url, headers=headers)
    prepped = request.prepare()

    try:
        response = session.send(prepped)
    except Exception as error:
        logging.error('A problem has occured connecting to the URL %s',url)
        logging.error(error)
        sys.exit()

    if response.status_code == 200:
        logging.info('Request status_code: %s', response.status_code)
        device_list = response.json()
    else:
        logging.error('Response Error - status_code: %s url: %s', response.status_code, url)
        sys.exit()

    return device_list

def print_devices(device_list):
    """
    Pass in a list of devices from the webex API and print it in a human readable form
    """
    print(f'{"displayName":<20} {"IP":<18} {"MAC":<18} {"serial":<}')
    for i in device_list['items']:
        #print('{:<20} {:<18} {:<18} {:<}'.format(i['displayName'], i['ip'], i['mac'], i['serial']))
        print(f'{i["displayName"]:<20} {i["ip"]:<18} {i["mac"]:<18} {i["serial"]:<}')

def main():
    """
    Run the script
    """
    #Start logging
    #logging.basicConfig(level='DEBUG',\
        #format='%(asctime)s-%(levelname)s-%(funcName)s()-%(message)s',
        #filename='log.txt'
        #)

    logging.basicConfig(level='INFO',\
        format='%(asctime)s-%(levelname)s-%(funcName)s()-%(message)s'
        )

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #Go read the secrete credentials from a file
    logging.info('Reading config file info')
    username, password, client_id, client_secret, redirect_url, scope, \
        oauth_url, adp_proxies = read_credentials()
    proxy_dict = {}
    proxy_dict['https'] = adp_proxies

    #Drive selenium through an OAuth interaction and get back a code
    logging.info('Beginning web login')
    auth_code = selenium_action(oauth_url, username, password)
    logging.info('auth_code: %s ...',auth_code[0:30])

    #Prepare the attributes of a request to the webex access token API
    token_url = 'https://webexapis.com/v1/access_token'
    token_method = 'POST'
    token_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    token_payload = 'grant_type=authorization_code&client_id='+client_id+\
        '&client_secret='+client_secret+'&code='+auth_code+\
        '&redirect_uri=https%3A%2F%2Fwww.jessico.dev%2Fnac'

    #Get the access and refresh token
    access_info = get_access_token\
        (token_method, token_url, token_headers, token_payload, proxy_dict)
    access_token = access_info['access_token']
    access_expires = access_info['expires_in']
    access_refresh = access_info['refresh_token']
    access_rexpires = access_info['refresh_token_expires_in']
    access_type = access_info['token_type']
    logging.info('access_token: %s ...',access_token[0:20])

    #Make a request against the Control Hub API
    device_list = get_devices(access_token, proxy_dict)

    #Pass the results to a printing function for human display
    print_devices(device_list)

if __name__ == "__main__":
    main()
