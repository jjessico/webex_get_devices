Webex Control Hub (https://admin.webex.com) offers a set of APIs through which the configuration of webex users and devices can be read and changed.
In order to access these APIs you must first build an "Integration" in the Webex Developer Portal.
Once you do that you have to sign in to the Integration interactively with a browser in order to get an OAuth code.
After you have an OAuth token you have to exchange that for an access token.
Then the access token allows you to make requests to the API.
On guidance from Cisco they view driving a headless browser as the optimal way to get an OAuth code.

This script goes through a non 2FA/OTP OAuth exchange with the Integration to get a token.
It then exchanges the code for an access token.
The access token is then used to retrieve a list of devices as proof it works.