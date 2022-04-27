#!/usr/bin/env python3
import urllib.request, json 
import getpass
import requests
from bs4 import BeautifulSoup


def get_form_details(form):
    """Returns the HTML details of a form,
    including action, method and list of form controls (inputs, etc)"""
    details = {}
    # get the form action (requested URL)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, DELETE, etc)
    # if not specified, GET is the default in HTML
    method = form.attrs.get("method", "get").lower()
    # get all form inputs
    inputs = []
    for input_tag in form.find_all("input"):
        # get type of input form control
        input_type = input_tag.attrs.get("type", "text")
        # get name attribute
        input_name = input_tag.attrs.get("name")
        # get the default value of that input tag
        input_value =input_tag.attrs.get("value", "")
        # add everything to that list
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    data = {}
    for input_tag in inputs:
        if input_tag["type"] == "hidden":
            # if it's hidden, use the default value
            data[input_tag["name"]] = input_tag["value"]
        elif input_tag["type"] != "submit":
            # all others except submit, prompt the user to set it
            value = input(f"Enter the value of the field '{input_tag['name']}' (type: {input_tag['type']}): ")
            data[input_tag["name"]] = value
    return action, method, data
package_id = 1621
url = f"https://splunkbase.splunk.com/api/v1/app/{package_id}/?include=releases,releases.content,releases.splunk_compatibility,releases.cim_compatibility,release,release.content,release.cim_compatibility,release.splunk_compatibility&instance_type=cloud"
urlauth = "https://account.splunk.com/api/v1/okta/auth"
username = input("Username: ")
password = getpass.getpass()
session = requests.session()
# Base auth with okta, store cookies
auth_req = session.post(urlauth, json={"username": username, "password": password}).json()
if ("status_code" in auth_req and auth_req['status_code'] != 200):
    print("Error authenticating, response: ",auth_req['message'])
    exit(1)
print("Authenticated, submitting okta intersitual")
data = session.get(url).json()
# Grab the download url for the first release. The first release actually returns a okta intersitual page that needs to be resolved and submitted
soup = BeautifulSoup(session.get(data["release"]["path"]).content, "html.parser")
# Scrape out the intersitual page and submit it
action, method, form_data = get_form_details(soup.find("form"))
if method == "post":
    session.post(action, data=form_data)
elif method == "get":
    session.get(action, data=form_data)
print("Successfully authenticated, downloading packages")
app_name = data["appid"]
# Now that that is done, we can freely download whatever packages we want.
for release in data["releases"]:
    version = release["title"]
    path = release["path"]
    splunk_compatibility = release["splunk_compatibility"]
    cim_compatibility = release["cim_compatibility"]
    product_compatibility = release["product_compatibility"]
    with open(f"{app_name} - {version}.tar.gz", "wb") as f:
        f.write(session.get(path).content)