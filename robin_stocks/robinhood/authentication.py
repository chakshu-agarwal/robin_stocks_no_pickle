"""Contains all functions for the purpose of logging in and out to Robinhood."""
import getpass
import os
import pickle
import random

from robin_stocks.robinhood.helper import *
from robin_stocks.robinhood.urls import *
import boto3
from botocore.client import Config
from botocore.exceptions import NoCredentialsError

class InputRequiredException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def generate_device_token():
    """This function will generate a token used when loggin on.

    :returns: A string representing the token.

    """
    rands = []
    for i in range(0, 16):
        r = random.random()
        rand = 4294967296.0 * r
        rands.append((int(rand) >> ((3 & i) << 3)) & 255)

    hexa = []
    for i in range(0, 256):
        hexa.append(str(hex(i+256)).lstrip("0x").rstrip("L")[1:])

    id = ""
    for i in range(0, 16):
        id += hexa[rands[i]]

        if (i == 3) or (i == 5) or (i == 7) or (i == 9):
            id += "-"

    return(id)


def respond_to_challenge(challenge_id, sms_code):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = challenge_url(challenge_id)
    payload = {
        'response': sms_code
    }
    return(request_post(url, payload))


def login(username=None, password=None, expiresIn=86400, scope='internal', by_sms=True, store_session=True, mfa_code=None, pickle_name=""):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. IF store_session = True, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param expiresIn: The time until your login session expires. This is in seconds.
    :type expiresIn: Optional[int]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param by_sms: Specifies whether to send an email(False) or an sms(True)
    :type by_sms: Optional[boolean]
    :param store_session: Specifies whether to save the log in authorization
        for future log ins.
    :type store_session: Optional[boolean]
    :param mfa_code: MFA token if enabled.
    :type mfa_code: Optional[str]
    :param pickle_name: Allows users to name Pickle token file in order to switch
        between different accounts without having to re-login every time.
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    device_token = generate_device_token()
    
    # Challenge type is used if not logging in with two-factor authentication.
    if by_sms:
        challenge_type = "sms"
    else:
        challenge_type = "email"

    url = login_url()
    payload = {
        'client_id': 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS',
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'challenge_type': challenge_type,
        'device_token': device_token
    }

    if mfa_code:
        payload['mfa_code'] = mfa_code

    # If session_store set to True, then define pickle_path
    if store_session:
      
        s3_bucket_name = os.environ.get('PICKLE_S3_BUCKET_NAME')
        s3_file_name = "robinhood" + pickle_name + ".pickle"

        my_config = Config(
            region_name = 'us-east-2',
            signature_version = 's3v4'
        )

        try:
            s3 = boto3.client(
                's3',
                config=my_config
            )
        except NoCredentialsError:
            print("AWS Log In Issue")

        # If authentication has been stored in pickle file then load it. Stops login server from being pinged so much.
        try:
            response = s3.get_object(Bucket=s3_bucket_name, Key=s3_file_name)
            pickle_data = pickle.loads(response['Body'].read())
            access_token = pickle_data['access_token']
            token_type = pickle_data['token_type']
            refresh_token = pickle_data['refresh_token']
            # Set device_token to be the original device token when first logged in.
            pickle_device_token = pickle_data['device_token']
            payload['device_token'] = pickle_device_token
            # Set login status to True in order to try and get account info.
            set_login_state(True)
            update_session(
                'Authorization', '{0} {1}'.format(token_type, access_token))
            # Try to load account profile to check that authorization token is still valid.
            res = request_get(
                positions_url(), 'pagination', {'nonzero': 'true'}, jsonify_data=False)
            # Raises exception is response code is not 200.
            res.raise_for_status()
            return({'access_token': access_token, 'token_type': token_type,
                    'expires_in': expiresIn, 'scope': scope, 'detail': 'logged in using authentication in {0}'.format(s3_file_name),
                    'backup_code': None, 'refresh_token': refresh_token})
        except:
            print(
                "ERROR: There was an issue loading pickle file. Authentication may be expired - logging in normally.", file=get_output())
            set_login_state(False)
            update_session('Authorization', None)
    else:
        pass

    # Try to log in normally.
    if not username:
        username = input("Robinhood username: ")
        payload['username'] = username

    if not password:
        password = getpass.getpass("Robinhood password: ")
        payload['password'] = password

    data = request_post(url, payload)
    # Handle case where mfa or challenge is required.
    if data:
        if 'mfa_required' in data and mfa_code is None:
            raise InputRequiredException("Please type in the MFA code")
        elif 'challenge' in data:
            challenge_id = data['challenge']['id']
            sms_code = input('Enter Robinhood code for validation: ')
            res = respond_to_challenge(challenge_id, sms_code)
            while 'challenge' in res and res['challenge']['remaining_attempts'] > 0:
                sms_code = input('That code was not correct. {0} tries remaining. Please type in another code: '.format(
                    res['challenge']['remaining_attempts']))
                res = respond_to_challenge(challenge_id, sms_code)
            update_session(
                'X-ROBINHOOD-CHALLENGE-RESPONSE-ID', challenge_id)
            data = request_post(url, payload)
        # Update Session data with authorization or raise exception with the information present in data.
        if 'access_token' in data:
            token = '{0} {1}'.format(data['token_type'], data['access_token'])
            update_session('Authorization', token)
            set_login_state(True)
            data['detail'] = "logged in with brand new authentication code."
            if store_session:
                # Save the authentication data to S3 bucket
                s3.put_object(Body=pickle.dumps({'token_type': data['token_type'],
                                                 'access_token': data['access_token'],
                                                 'refresh_token': data['refresh_token'],
                                                 'device_token': payload['device_token']}), Bucket=s3_bucket_name, Key=s3_file_name)
        else:
            raise Exception(data['detail'])
    else:
        raise Exception('Error: Trouble connecting to robinhood API. Check internet connection.')
    return(data)


@login_required
def logout():
    """Removes authorization from the session header.

    :returns: None

    """
    set_login_state(False)
    update_session('Authorization', None)
