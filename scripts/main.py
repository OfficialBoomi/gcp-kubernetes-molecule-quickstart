import sys
import logging
import requests
import base64
import urllib3
from google.cloud import storage

logger = logging.getLogger(__name__)


def _create_auth_headers(username, password):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(urllib3.util.make_headers(basic_auth=f"{username}:{password}"))
    return headers


def _verify_boomi_licensing(username, password,account, atomtype):
    if atomtype=="Privatecloud" :
      _agheaders = _create_auth_headers(username, password)
      API_URL = f"https://api.boomi.com/api/rest/v1/{account}/AccountGroup/query"
      resp = requests.post(API_URL, headers=_agheaders)
      resp.raise_for_status()
      json_resp = resp.json()

      number_of_results = json_resp["numberOfResults"]
      print("number_of_results:{}".format(number_of_results))

      if number_of_results>=1 :        
          print("Account Group is enabled.")   
      else:
         logger.error("Exception: Boomi account group  is not present")
         raise Exception(f"Boomi account group {account} is not present.") 
        
    else:
     _headers = _create_auth_headers(username, password)
     API_URL1= f"https://api.boomi.com/api/rest/v1/{account}/Account/{account}"
     resp = requests.get(API_URL1, headers=_headers)
     resp.raise_for_status()
     json_resp = resp.json()

     account_status = json_resp["status"]
     molecule_licenses_purchased = json_resp["molecule"]["purchased"]
     molecule_licenses_used = json_resp["molecule"]["used"]

     # Is the account active?
     if account_status == "active":
        logger.info(f"Account is active")
     else:
        logger.error("Exception: Boomi account is inactive")
        raise Exception(f"Boomi account {account} is inactive.")

     # Do we have license entitlements at all?
     if molecule_licenses_purchased > molecule_licenses_used:
        logger.info(
            f"Licenses are available - Purchased: {molecule_licenses_purchased} / Used: {molecule_licenses_used}"
        )
     else:
        logger.error("Exception: No enterprise license available")
        raise Exception(
            f"No Molecule licenses for account {account} are available. Purchased: {molecule_licenses_purchased}, Used: {molecule_licenses_used}"
        )


def _generate_install_token(username, password, account_id, token_type, timeout):
    REQ_TOKEN_TYPES = ["MOLECULE"]
    if token_type.upper() not in REQ_TOKEN_TYPES:
        raise Exception(f"Parameter TokenType must be one of: {str(REQ_TOKEN_TYPES)}")

    _headers = _create_auth_headers(username, password)
    API_URL = f"https://api.boomi.com/api/rest/v1/{account_id}/InstallerToken/"
    payload = {"installType": token_type, "durationMinutes": int(timeout)}
    logger.info(payload)
    resp = requests.post(API_URL, headers=_headers, json=payload)
    resp.raise_for_status()
    rj = resp.json()

    return rj["token"]


def auth_and_licensing_logic(username, password, account_id, token_type, token_timeout, atomtype):
    # Verify licensing
    _verify_boomi_licensing(username, password, account_id, atomtype)
    if username.startswith("BOOMI_TOKEN."):
        # Generate install token
        token = _generate_install_token(
            username, password, account_id, token_type, token_timeout
        )
        return token

def handler(request):
    STATUS = "SUCCESS"
    molecule_token = None
    try:
        request_json = request.get_json()
        BoomiUsername = request_json['BoomiUsername']
        BoomiAuthenticationType= request_json['boomiAuthenticationType']
        BoomiAuthenticationType = BoomiAuthenticationType.strip()
        BoomiPassword= request_json['BoomiPassword']
        BoomiAccountID=request_json['BoomiAccountID']
        TokenType= request_json['TokenType']
        TokenTimeout= request_json['TokenTimeout']
        bucketname= request_json['bucketname']
        atomtype= request_json['atomtype']
        
        if BoomiAuthenticationType.upper() =="TOKEN":
         molecule_token = auth_and_licensing_logic("BOOMI_TOKEN."+BoomiUsername, BoomiPassword, BoomiAccountID, TokenType.upper(), TokenTimeout,atomtype)
         client = storage.Client()
         bucket = client.get_bucket(bucketname)
         blob = bucket.blob('token.txt')         
         blob.upload_from_string(base64.b64encode(molecule_token.encode('utf-8')))
        else:
         molecule_token = auth_and_licensing_logic(BoomiUsername, BoomiPassword, BoomiAccountID, TokenType.upper(), TokenTimeout,atomtype)        
         client = storage.Client()
         bucket = client.get_bucket(bucketname)
         blob = bucket.blob('token.txt')
         blob.upload_from_string(base64.b64encode(BoomiPassword.encode('utf-8')))
    except requests.exceptions.RequestException as err:
        logging.error(err)
        STATUS = "FAILED"
    except Exception as err:
        logging.error(err)
        STATUS = "FAILED"
    finally:
        print("status:{},token:{}".format(STATUS,molecule_token))
