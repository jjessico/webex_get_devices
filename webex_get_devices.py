import logging
import sys
import re
import requests
from configparser import ConfigParser
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def read_credentials():
    """
    Read a webex user e-mail and password from a config file.  Return user and password.
    """
    parser = ConfigParser(interpolation=None)
    config_section = 'webex'
    config_path = '..\\..\\restricted\webex.ini'
    try:
        parser.read(config_path)
    except:
        logging.error('Cannot read config from {}'.format(config_path))
        sys.exit('Unable to read credential file')

    if parser.has_section(config_section):
        config_params = parser.items(config_section)
        username = config_params[0][1]
        password = config_params[1][1]
        client_id = config_params[2][1]
        client_secret = config_params[3][1]
        redirect_url = config_params[4][1]
        scope = config_params[5][1]
        oauth_url = config_params[6][1]
    else:
        logging.error('Cannot read section {}'.format(config_section))
        sys.exit('No webex section of config file')

    return username, password, client_id, client_secret, redirect_url, scope, oauth_url

def selenium_action(url, username, password):
    """
    Go to the oauth URL for a webex integration with Selenium. Put in an email
    press submit.  Put in a password, press submit.
    """
    selenium_options = Options()
    #selenium_options.headless = True
    driver = webdriver.Firefox(options=selenium_options)
    driver.get(url)
    try:
        email_input = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.ID, 'IDToken1'))
        )
    except:
        logging.error("Unable to find email box on login page")
        driver.quit()
        sys.exit()

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

    password_input.send_keys(password)

    try:
        password_submit = driver.find_element(By.ID, 'Button1')
        password_submit.click()
    except Exception as selenium_failure:
        redirect_error = selenium_failure.msg
        code = parse_redirect(redirect_error)
        driver.quit()
        return code

    driver.quit()

def parse_redirect(error_message):
    """
    From the Selenium error message extract the code, which is everything
    between the code= and &state text in the URL that fails to resolve
    """
    match = re.match(r'(^.*code%3D)(.*)(%26state.*)', error_message)
    return match[2]

def get_access_token(method, url, headers, payload):
    """Make an HTTP request with a specified METHOD to a desired URL with given
    headers.  Return the page contents as a BS4 object if the response is a 200
    """
    logging.info('url: %s', url)
    logging.info('headers: %s', headers)

    session = requests.Session()
    session.trust_env = True
    session.verify = True

    request = requests.Request(method, url, headers=headers, data=payload)
    prepped = request.prepare()

    try:
        response = session.send(prepped)
    except Exception as error:
        logging.error('A problem has occured connecting to the URL {}'.format(url))
        sys.exit()

    if response.status_code == 200:
        logging.info('Request status_code: %s', response.status_code)
        data = response.json()
        return data
    else:
        logging.error('Response Error - status_code: %s url: %s', response.status_code, url)
        sys.exit()

    return False

def get_devices(access_token):
    session = requests.Session()
    session.trust_env = True
    session.verify = True
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
        logging.error('A problem has occured connecting to the URL {}'.format(url))
        sys.exit()

    if response.status_code == 200:
        device_list = response.json()
    else:
        logging.error('Response Error - status_code: %s url: %s', response.status_code, url)
        sys.exit()

    return device_list

def print_devices(device_list):
    print('{:<20} {:<18} {:<18} {:<}'.format('displayName', 'IP', 'MAC', 'serial'))
    for i in device_list['items']:
        print('{:<20} {:<18} {:<18} {:<}'.format(i['displayName'], i['ip'], i['mac'], i['serial']))

def main():
    #Start logging
    logging.basicConfig(level='INFO',\
        format='%(asctime)s-%(levelname)s-%(funcName)s()-%(message)s')

    logging.info('Reading config file info')
    username, password, client_id, client_secret, redirect_url, scope, oauth_url = read_credentials()

    logging.info('Beginning web login')
    auth_code = selenium_action(oauth_url, username, password)
    logging.info('auth_code: {} ...'.format(auth_code[0:30]))

    token_url = 'https://webexapis.com/v1/access_token'
    token_method = 'POST'
    token_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    token_payload = 'grant_type=authorization_code&client_id=C80f1734039c293360147797516ee8269e0914d69a9f3ffeda69bb8ef3b465dd5&client_secret=10bc5770f6a58130998424bcee738d278dae58cadcee6c80c30b051097561ab4&code='+auth_code+'&redirect_uri=https%3A%2F%2Fwww.jessico.dev%2Fnac'

    access_info = get_access_token(token_method, token_url, token_headers, token_payload)
    access_token = access_info['access_token']
    access_expires = access_info['expires_in']
    access_refresh = access_info['refresh_token']
    access_rexpires = access_info['refresh_token_expires_in']
    access_type = access_info['token_type']
    logging.info('access_token: {} ...'.format(access_token[0:20]))

    device_list = get_devices(access_token)
    print_devices(device_list)

if __name__ == "__main__":
    main()


