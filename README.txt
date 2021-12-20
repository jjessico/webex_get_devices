Webex Control Hub (https://admin.webex.com) offers a set of APIs through which the configuration of webex users and devices can be read and changed.
In order to access these APIs you must first build an "Integration" in the Webex Developer Portal.
Once you do that you have to sign in to the Integration interactively with a browser in order to get an OAuth code.
After you have an OAuth token you have to exchange that for an access token.
Then the access token allows you to make requests to the API.
On guidance from Cisco they view driving a headless browser as the optimal way to get an OAuth code.

This script goes through a non 2FA/OTP OAuth exchange with the Integration to get a token.
1) Reads required credentials and configs from an .ini file
2) Uses selenium to drive a chrome browser to act as a user and login
3) Examines the request history of the selenium browser to find the access code
4) Uses Requests to exchange the code for an access token.
5) Uses the access token with Requests to retrieve a list of devices as proof it works.

Requirements to Run
1) Python 3
2) Selenium
3) Requests
4) chrome webdriver in a folder in the system path

Requirements to Function
1) Cisco Webex Integration:
-Client Secret
-Client ID
-Oauth URL
-Integraiton scope
2) Corporate proxy port, URL, and credentials
3) Webex user & password
 

TODO
1) Retrive all credentials from Vault
2) Navigate through an MSFT Azure SSO login instead of Cisco standalone
3) Make selenium exception and OK path get code in the same way
4) Handle paginated webex device lists

#Example
PS python.exe webex_get_devices_chrome.py
2021-12-19 18:03:44,517-INFO-main()-Reading config file info
2021-12-19 18:03:44,519-INFO-read_credentials()-Config read from section webex in file ..\..\restricted\webex.ini
2021-12-19 18:03:44,519-INFO-main()-Beginning web login

DevTools listening on ws://127.0.0.1:18079/devtools/browser/a8af5773-b0cf-4799-b928-6eb3562cab97
2021-12-19 18:03:51,460-INFO-selenium_action()-Returning integration code without exception handling
2021-12-19 18:03:54,622-INFO-main()-auth_code: MGM2QmJhMfakefakefakemJkLTk1MD ...
2021-12-19 18:03:54,622-INFO-get_access_token()-url: https://webexapis.com/v1/access_token
2021-12-19 18:03:54,622-INFO-get_access_token()-headers: {'Content-Type': 'application/x-www-form-urlencoded'}
2021-12-19 18:03:55,444-INFO-get_access_token()-Request status_code: 200
2021-12-19 18:03:55,446-INFO-main()-access_token: NQI3LfakefakefakeUzMC60 ...
2021-12-19 18:03:56,290-INFO-get_devices()-Request status_code: 200
displayName          IP                 MAC                serial
EFT03-WS2            192.168.254.74     EC:CC:7A:AA:87:11  FOC9999NLP1
US-CMG-OFC25         192.168.1.200      C4:1F:BB:BF:A9:A2  FOC9999B1E1