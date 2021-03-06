# swagger_client
No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

This Python package is automatically generated by the [Swagger Codegen](https://github.com/swagger-api/swagger-codegen) project:

- API version: Latest
- Package version: 1.0.0
- Build package: io.swagger.codegen.languages.PythonClientCodegen

## Requirements.

Python 2.7 and 3.4+

## Installation & Usage
### pip install

If the python package is hosted on Github, you can install directly from Github

```sh
pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git
```
(you may need to run `pip` with root permission: `sudo pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git`)

Then import the package:
```python
import swagger_client 
```

### Setuptools

Install via [Setuptools](http://pypi.python.org/pypi/setuptools).

```sh
python setup.py install --user
```
(or `sudo python setup.py install` to install the package for all users)

Then import the package:
```python
import swagger_client
```

## Getting Started

Please follow the [installation procedure](#installation--usage) and then run the following:

```python
from __future__ import print_function
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# Configure OAuth2 access token for authorization: orcid_two_legs
swagger_client.configuration.access_token = 'YOUR_ACCESS_TOKEN'
# create an instance of the API class
api_instance = swagger_client.MemberAPIV20Api()
orcid = 'orcid_example' # str | 
body = swagger_client.NotificationPermission() # NotificationPermission |  (optional)

try:
    # Add a notification
    api_response = api_instance.add_permission_notification(orcid, body=body)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling MemberAPIV20Api->add_permission_notification: %s\n" % e)

```

## Documentation for API Endpoints

All URIs are relative to *https://api.orcid.org*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*MemberAPIV20Api* | [**add_permission_notification**](docs/MemberAPIV20Api.md#add_permission_notification) | **POST** /v2.0/{orcid}/notification-permission | Add a notification
*MemberAPIV20Api* | [**create_address**](docs/MemberAPIV20Api.md#create_address) | **POST** /v2.0/{orcid}/address | Add an address
*MemberAPIV20Api* | [**create_education**](docs/MemberAPIV20Api.md#create_education) | **POST** /v2.0/{orcid}/education | Create an Education
*MemberAPIV20Api* | [**create_employment**](docs/MemberAPIV20Api.md#create_employment) | **POST** /v2.0/{orcid}/employment | Create an Employment
*MemberAPIV20Api* | [**create_external_identifier**](docs/MemberAPIV20Api.md#create_external_identifier) | **POST** /v2.0/{orcid}/external-identifiers | Add external identifier
*MemberAPIV20Api* | [**create_funding**](docs/MemberAPIV20Api.md#create_funding) | **POST** /v2.0/{orcid}/funding | Create a Funding
*MemberAPIV20Api* | [**create_group_id_record**](docs/MemberAPIV20Api.md#create_group_id_record) | **POST** /v2.0/group-id-record | Create a Group
*MemberAPIV20Api* | [**create_keyword**](docs/MemberAPIV20Api.md#create_keyword) | **POST** /v2.0/{orcid}/keywords | Add keyword
*MemberAPIV20Api* | [**create_other_name**](docs/MemberAPIV20Api.md#create_other_name) | **POST** /v2.0/{orcid}/other-names | Add other name
*MemberAPIV20Api* | [**create_peer_review**](docs/MemberAPIV20Api.md#create_peer_review) | **POST** /v2.0/{orcid}/peer-review | Create a Peer Review
*MemberAPIV20Api* | [**create_researcher_url**](docs/MemberAPIV20Api.md#create_researcher_url) | **POST** /v2.0/{orcid}/researcher-urls | Add a new researcher url for an ORCID ID
*MemberAPIV20Api* | [**create_work**](docs/MemberAPIV20Api.md#create_work) | **POST** /v2.0/{orcid}/work | Create a Work
*MemberAPIV20Api* | [**create_works**](docs/MemberAPIV20Api.md#create_works) | **POST** /v2.0/{orcid}/works | Create a listo of Work
*MemberAPIV20Api* | [**delete_address**](docs/MemberAPIV20Api.md#delete_address) | **DELETE** /v2.0/{orcid}/address/{putCode} | Delete an address
*MemberAPIV20Api* | [**delete_education**](docs/MemberAPIV20Api.md#delete_education) | **DELETE** /v2.0/{orcid}/education/{putCode} | Delete an Education
*MemberAPIV20Api* | [**delete_employment**](docs/MemberAPIV20Api.md#delete_employment) | **DELETE** /v2.0/{orcid}/employment/{putCode} | Delete an Employment
*MemberAPIV20Api* | [**delete_external_identifier**](docs/MemberAPIV20Api.md#delete_external_identifier) | **DELETE** /v2.0/{orcid}/external-identifiers/{putCode} | Delete external identifier
*MemberAPIV20Api* | [**delete_funding**](docs/MemberAPIV20Api.md#delete_funding) | **DELETE** /v2.0/{orcid}/funding/{putCode} | Delete a Funding
*MemberAPIV20Api* | [**delete_group_id_record**](docs/MemberAPIV20Api.md#delete_group_id_record) | **DELETE** /v2.0/group-id-record/{putCode} | Delete a Group
*MemberAPIV20Api* | [**delete_keyword**](docs/MemberAPIV20Api.md#delete_keyword) | **DELETE** /v2.0/{orcid}/keywords/{putCode} | Delete keyword
*MemberAPIV20Api* | [**delete_other_name**](docs/MemberAPIV20Api.md#delete_other_name) | **DELETE** /v2.0/{orcid}/other-names/{putCode} | Delete other name
*MemberAPIV20Api* | [**delete_peer_review**](docs/MemberAPIV20Api.md#delete_peer_review) | **DELETE** /v2.0/{orcid}/peer-review/{putCode} | Delete a Peer Review
*MemberAPIV20Api* | [**delete_researcher_url**](docs/MemberAPIV20Api.md#delete_researcher_url) | **DELETE** /v2.0/{orcid}/researcher-urls/{putCode} | Delete one researcher url from an ORCID ID
*MemberAPIV20Api* | [**delete_work**](docs/MemberAPIV20Api.md#delete_work) | **DELETE** /v2.0/{orcid}/work/{putCode} | Delete a Work
*MemberAPIV20Api* | [**edit_address**](docs/MemberAPIV20Api.md#edit_address) | **PUT** /v2.0/{orcid}/address/{putCode} | Edit an address
*MemberAPIV20Api* | [**edit_external_identifier**](docs/MemberAPIV20Api.md#edit_external_identifier) | **PUT** /v2.0/{orcid}/external-identifiers/{putCode} | Edit external identifier
*MemberAPIV20Api* | [**edit_keyword**](docs/MemberAPIV20Api.md#edit_keyword) | **PUT** /v2.0/{orcid}/keywords/{putCode} | Edit keyword
*MemberAPIV20Api* | [**edit_other_name**](docs/MemberAPIV20Api.md#edit_other_name) | **PUT** /v2.0/{orcid}/other-names/{putCode} | Edit other name
*MemberAPIV20Api* | [**edit_researcher_url**](docs/MemberAPIV20Api.md#edit_researcher_url) | **PUT** /v2.0/{orcid}/researcher-urls/{putCode} | Edits researcher url for an ORCID ID
*MemberAPIV20Api* | [**flag_as_archived_permission_notification**](docs/MemberAPIV20Api.md#flag_as_archived_permission_notification) | **DELETE** /v2.0/{orcid}/notification-permission/{id} | Archive a notification
*MemberAPIV20Api* | [**search_by_query_xml**](docs/MemberAPIV20Api.md#search_by_query_xml) | **GET** /v2.0/search | Search records
*MemberAPIV20Api* | [**update_education**](docs/MemberAPIV20Api.md#update_education) | **PUT** /v2.0/{orcid}/education/{putCode} | Update an Education
*MemberAPIV20Api* | [**update_employment**](docs/MemberAPIV20Api.md#update_employment) | **PUT** /v2.0/{orcid}/employment/{putCode} | Update an Employment
*MemberAPIV20Api* | [**update_funding**](docs/MemberAPIV20Api.md#update_funding) | **PUT** /v2.0/{orcid}/funding/{putCode} | Update a Funding
*MemberAPIV20Api* | [**update_group_id_record**](docs/MemberAPIV20Api.md#update_group_id_record) | **PUT** /v2.0/group-id-record/{putCode} | Update a Group
*MemberAPIV20Api* | [**update_peer_review**](docs/MemberAPIV20Api.md#update_peer_review) | **PUT** /v2.0/{orcid}/peer-review/{putCode} | Update a Peer Review
*MemberAPIV20Api* | [**update_work**](docs/MemberAPIV20Api.md#update_work) | **PUT** /v2.0/{orcid}/work/{putCode} | Update a Work
*MemberAPIV20Api* | [**view_activities**](docs/MemberAPIV20Api.md#view_activities) | **GET** /v2.0/{orcid}/activities | Fetch all activities
*MemberAPIV20Api* | [**view_address**](docs/MemberAPIV20Api.md#view_address) | **GET** /v2.0/{orcid}/address/{putCode} | Fetch an address
*MemberAPIV20Api* | [**view_addresses**](docs/MemberAPIV20Api.md#view_addresses) | **GET** /v2.0/{orcid}/address | Fetch all addresses of a profile
*MemberAPIV20Api* | [**view_biography**](docs/MemberAPIV20Api.md#view_biography) | **GET** /v2.0/{orcid}/biography | Get biography details
*MemberAPIV20Api* | [**view_client**](docs/MemberAPIV20Api.md#view_client) | **GET** /v2.0/client/{client_id} | Fetch client details
*MemberAPIV20Api* | [**view_education**](docs/MemberAPIV20Api.md#view_education) | **GET** /v2.0/{orcid}/education/{putCode} | Fetch an Education
*MemberAPIV20Api* | [**view_education_summary**](docs/MemberAPIV20Api.md#view_education_summary) | **GET** /v2.0/{orcid}/education/summary/{putCode} | Fetch an Education summary
*MemberAPIV20Api* | [**view_educations**](docs/MemberAPIV20Api.md#view_educations) | **GET** /v2.0/{orcid}/educations | Fetch all educations
*MemberAPIV20Api* | [**view_emails**](docs/MemberAPIV20Api.md#view_emails) | **GET** /v2.0/{orcid}/email | Fetch all emails for an ORCID ID
*MemberAPIV20Api* | [**view_employment**](docs/MemberAPIV20Api.md#view_employment) | **GET** /v2.0/{orcid}/employment/{putCode} | Fetch an Employment
*MemberAPIV20Api* | [**view_employment_summary**](docs/MemberAPIV20Api.md#view_employment_summary) | **GET** /v2.0/{orcid}/employment/summary/{putCode} | Fetch an Employment Summary
*MemberAPIV20Api* | [**view_employments**](docs/MemberAPIV20Api.md#view_employments) | **GET** /v2.0/{orcid}/employments | Fetch all employments
*MemberAPIV20Api* | [**view_external_identifier**](docs/MemberAPIV20Api.md#view_external_identifier) | **GET** /v2.0/{orcid}/external-identifiers/{putCode} | Fetch external identifier
*MemberAPIV20Api* | [**view_external_identifiers**](docs/MemberAPIV20Api.md#view_external_identifiers) | **GET** /v2.0/{orcid}/external-identifiers | Fetch external identifiers
*MemberAPIV20Api* | [**view_funding**](docs/MemberAPIV20Api.md#view_funding) | **GET** /v2.0/{orcid}/funding/{putCode} | Fetch a Funding
*MemberAPIV20Api* | [**view_funding_summary**](docs/MemberAPIV20Api.md#view_funding_summary) | **GET** /v2.0/{orcid}/funding/summary/{putCode} | Fetch a Funding Summary
*MemberAPIV20Api* | [**view_fundings**](docs/MemberAPIV20Api.md#view_fundings) | **GET** /v2.0/{orcid}/fundings | Fetch all fundings
*MemberAPIV20Api* | [**view_group_id_record**](docs/MemberAPIV20Api.md#view_group_id_record) | **GET** /v2.0/group-id-record/{putCode} | Fetch a Group
*MemberAPIV20Api* | [**view_group_id_records**](docs/MemberAPIV20Api.md#view_group_id_records) | **GET** /v2.0/group-id-record | Fetch Groups
*MemberAPIV20Api* | [**view_keyword**](docs/MemberAPIV20Api.md#view_keyword) | **GET** /v2.0/{orcid}/keywords/{putCode} | Fetch keyword
*MemberAPIV20Api* | [**view_keywords**](docs/MemberAPIV20Api.md#view_keywords) | **GET** /v2.0/{orcid}/keywords | Fetch keywords
*MemberAPIV20Api* | [**view_other_name**](docs/MemberAPIV20Api.md#view_other_name) | **GET** /v2.0/{orcid}/other-names/{putCode} | Fetch Other name
*MemberAPIV20Api* | [**view_other_names**](docs/MemberAPIV20Api.md#view_other_names) | **GET** /v2.0/{orcid}/other-names | Fetch Other names
*MemberAPIV20Api* | [**view_peer_review**](docs/MemberAPIV20Api.md#view_peer_review) | **GET** /v2.0/{orcid}/peer-review/{putCode} | Fetch a Peer Review
*MemberAPIV20Api* | [**view_peer_review_summary**](docs/MemberAPIV20Api.md#view_peer_review_summary) | **GET** /v2.0/{orcid}/peer-review/summary/{putCode} | Fetch a Peer Review Summary
*MemberAPIV20Api* | [**view_peer_reviews**](docs/MemberAPIV20Api.md#view_peer_reviews) | **GET** /v2.0/{orcid}/peer-reviews | Fetch all peer reviews
*MemberAPIV20Api* | [**view_permission_notification**](docs/MemberAPIV20Api.md#view_permission_notification) | **GET** /v2.0/{orcid}/notification-permission/{id} | Fetch a notification by id
*MemberAPIV20Api* | [**view_person**](docs/MemberAPIV20Api.md#view_person) | **GET** /v2.0/{orcid}/person | Fetch person details
*MemberAPIV20Api* | [**view_personal_details**](docs/MemberAPIV20Api.md#view_personal_details) | **GET** /v2.0/{orcid}/personal-details | Fetch personal details for an ORCID ID
*MemberAPIV20Api* | [**view_record**](docs/MemberAPIV20Api.md#view_record) | **GET** /v2.0/{orcid}{ignore} | Fetch record details
*MemberAPIV20Api* | [**view_researcher_url**](docs/MemberAPIV20Api.md#view_researcher_url) | **GET** /v2.0/{orcid}/researcher-urls/{putCode} | Fetch one researcher url for an ORCID ID
*MemberAPIV20Api* | [**view_researcher_urls**](docs/MemberAPIV20Api.md#view_researcher_urls) | **GET** /v2.0/{orcid}/researcher-urls | Fetch all researcher urls for an ORCID ID
*MemberAPIV20Api* | [**view_specified_works**](docs/MemberAPIV20Api.md#view_specified_works) | **GET** /v2.0/{orcid}/works/{putCodes} | Fetch specified works
*MemberAPIV20Api* | [**view_work**](docs/MemberAPIV20Api.md#view_work) | **GET** /v2.0/{orcid}/work/{putCode} | Fetch a Work
*MemberAPIV20Api* | [**view_work_summary**](docs/MemberAPIV20Api.md#view_work_summary) | **GET** /v2.0/{orcid}/work/summary/{putCode} | Fetch a Work Summary
*MemberAPIV20Api* | [**view_works**](docs/MemberAPIV20Api.md#view_works) | **GET** /v2.0/{orcid}/works | Fetch all works
*MemberAPIV21Api* | [**add_permission_notification**](docs/MemberAPIV21Api.md#add_permission_notification) | **POST** /v2.1/{orcid}/notification-permission | Add a notification
*MemberAPIV21Api* | [**create_address**](docs/MemberAPIV21Api.md#create_address) | **POST** /v2.1/{orcid}/address | Add an address
*MemberAPIV21Api* | [**create_education**](docs/MemberAPIV21Api.md#create_education) | **POST** /v2.1/{orcid}/education | Create an Education
*MemberAPIV21Api* | [**create_employment**](docs/MemberAPIV21Api.md#create_employment) | **POST** /v2.1/{orcid}/employment | Create an Employment
*MemberAPIV21Api* | [**create_external_identifier**](docs/MemberAPIV21Api.md#create_external_identifier) | **POST** /v2.1/{orcid}/external-identifiers | Add external identifier
*MemberAPIV21Api* | [**create_funding**](docs/MemberAPIV21Api.md#create_funding) | **POST** /v2.1/{orcid}/funding | Create a Funding
*MemberAPIV21Api* | [**create_group_id_record**](docs/MemberAPIV21Api.md#create_group_id_record) | **POST** /v2.1/group-id-record | Create a Group
*MemberAPIV21Api* | [**create_keyword**](docs/MemberAPIV21Api.md#create_keyword) | **POST** /v2.1/{orcid}/keywords | Add keyword
*MemberAPIV21Api* | [**create_other_name**](docs/MemberAPIV21Api.md#create_other_name) | **POST** /v2.1/{orcid}/other-names | Add other name
*MemberAPIV21Api* | [**create_peer_review**](docs/MemberAPIV21Api.md#create_peer_review) | **POST** /v2.1/{orcid}/peer-review | Create a Peer Review
*MemberAPIV21Api* | [**create_researcher_url**](docs/MemberAPIV21Api.md#create_researcher_url) | **POST** /v2.1/{orcid}/researcher-urls | Add a new researcher url for an ORCID ID
*MemberAPIV21Api* | [**create_work**](docs/MemberAPIV21Api.md#create_work) | **POST** /v2.1/{orcid}/work | Create a Work
*MemberAPIV21Api* | [**create_works**](docs/MemberAPIV21Api.md#create_works) | **POST** /v2.1/{orcid}/works | Create a listo of Work
*MemberAPIV21Api* | [**delete_address**](docs/MemberAPIV21Api.md#delete_address) | **DELETE** /v2.1/{orcid}/address/{putCode} | Delete an address
*MemberAPIV21Api* | [**delete_education**](docs/MemberAPIV21Api.md#delete_education) | **DELETE** /v2.1/{orcid}/education/{putCode} | Delete an Education
*MemberAPIV21Api* | [**delete_employment**](docs/MemberAPIV21Api.md#delete_employment) | **DELETE** /v2.1/{orcid}/employment/{putCode} | Delete an Employment
*MemberAPIV21Api* | [**delete_external_identifier**](docs/MemberAPIV21Api.md#delete_external_identifier) | **DELETE** /v2.1/{orcid}/external-identifiers/{putCode} | Delete external identifier
*MemberAPIV21Api* | [**delete_funding**](docs/MemberAPIV21Api.md#delete_funding) | **DELETE** /v2.1/{orcid}/funding/{putCode} | Delete a Funding
*MemberAPIV21Api* | [**delete_group_id_record**](docs/MemberAPIV21Api.md#delete_group_id_record) | **DELETE** /v2.1/group-id-record/{putCode} | Delete a Group
*MemberAPIV21Api* | [**delete_keyword**](docs/MemberAPIV21Api.md#delete_keyword) | **DELETE** /v2.1/{orcid}/keywords/{putCode} | Delete keyword
*MemberAPIV21Api* | [**delete_other_name**](docs/MemberAPIV21Api.md#delete_other_name) | **DELETE** /v2.1/{orcid}/other-names/{putCode} | Delete other name
*MemberAPIV21Api* | [**delete_peer_review**](docs/MemberAPIV21Api.md#delete_peer_review) | **DELETE** /v2.1/{orcid}/peer-review/{putCode} | Delete a Peer Review
*MemberAPIV21Api* | [**delete_researcher_url**](docs/MemberAPIV21Api.md#delete_researcher_url) | **DELETE** /v2.1/{orcid}/researcher-urls/{putCode} | Delete one researcher url from an ORCID ID
*MemberAPIV21Api* | [**delete_work**](docs/MemberAPIV21Api.md#delete_work) | **DELETE** /v2.1/{orcid}/work/{putCode} | Delete a Work
*MemberAPIV21Api* | [**edit_address**](docs/MemberAPIV21Api.md#edit_address) | **PUT** /v2.1/{orcid}/address/{putCode} | Edit an address
*MemberAPIV21Api* | [**edit_external_identifier**](docs/MemberAPIV21Api.md#edit_external_identifier) | **PUT** /v2.1/{orcid}/external-identifiers/{putCode} | Edit external identifier
*MemberAPIV21Api* | [**edit_keyword**](docs/MemberAPIV21Api.md#edit_keyword) | **PUT** /v2.1/{orcid}/keywords/{putCode} | Edit keyword
*MemberAPIV21Api* | [**edit_other_name**](docs/MemberAPIV21Api.md#edit_other_name) | **PUT** /v2.1/{orcid}/other-names/{putCode} | Edit other name
*MemberAPIV21Api* | [**edit_researcher_url**](docs/MemberAPIV21Api.md#edit_researcher_url) | **PUT** /v2.1/{orcid}/researcher-urls/{putCode} | Edits researcher url for an ORCID ID
*MemberAPIV21Api* | [**flag_as_archived_permission_notification**](docs/MemberAPIV21Api.md#flag_as_archived_permission_notification) | **DELETE** /v2.1/{orcid}/notification-permission/{id} | Archive a notification
*MemberAPIV21Api* | [**search_by_query_xml**](docs/MemberAPIV21Api.md#search_by_query_xml) | **GET** /v2.1/search | Search records
*MemberAPIV21Api* | [**update_education**](docs/MemberAPIV21Api.md#update_education) | **PUT** /v2.1/{orcid}/education/{putCode} | Update an Education
*MemberAPIV21Api* | [**update_employment**](docs/MemberAPIV21Api.md#update_employment) | **PUT** /v2.1/{orcid}/employment/{putCode} | Update an Employment
*MemberAPIV21Api* | [**update_funding**](docs/MemberAPIV21Api.md#update_funding) | **PUT** /v2.1/{orcid}/funding/{putCode} | Update a Funding
*MemberAPIV21Api* | [**update_group_id_record**](docs/MemberAPIV21Api.md#update_group_id_record) | **PUT** /v2.1/group-id-record/{putCode} | Update a Group
*MemberAPIV21Api* | [**update_peer_review**](docs/MemberAPIV21Api.md#update_peer_review) | **PUT** /v2.1/{orcid}/peer-review/{putCode} | Update a Peer Review
*MemberAPIV21Api* | [**update_work**](docs/MemberAPIV21Api.md#update_work) | **PUT** /v2.1/{orcid}/work/{putCode} | Update a Work
*MemberAPIV21Api* | [**view_activities**](docs/MemberAPIV21Api.md#view_activities) | **GET** /v2.1/{orcid}/activities | Fetch all activities
*MemberAPIV21Api* | [**view_address**](docs/MemberAPIV21Api.md#view_address) | **GET** /v2.1/{orcid}/address/{putCode} | Fetch an address
*MemberAPIV21Api* | [**view_addresses**](docs/MemberAPIV21Api.md#view_addresses) | **GET** /v2.1/{orcid}/address | Fetch all addresses of a profile
*MemberAPIV21Api* | [**view_biography**](docs/MemberAPIV21Api.md#view_biography) | **GET** /v2.1/{orcid}/biography | Get biography details
*MemberAPIV21Api* | [**view_client**](docs/MemberAPIV21Api.md#view_client) | **GET** /v2.1/client/{client_id} | Fetch client details
*MemberAPIV21Api* | [**view_education**](docs/MemberAPIV21Api.md#view_education) | **GET** /v2.1/{orcid}/education/{putCode} | Fetch an Education
*MemberAPIV21Api* | [**view_education_summary**](docs/MemberAPIV21Api.md#view_education_summary) | **GET** /v2.1/{orcid}/education/summary/{putCode} | Fetch an Education summary
*MemberAPIV21Api* | [**view_educations**](docs/MemberAPIV21Api.md#view_educations) | **GET** /v2.1/{orcid}/educations | Fetch all educations
*MemberAPIV21Api* | [**view_emails**](docs/MemberAPIV21Api.md#view_emails) | **GET** /v2.1/{orcid}/email | Fetch all emails for an ORCID ID
*MemberAPIV21Api* | [**view_employment**](docs/MemberAPIV21Api.md#view_employment) | **GET** /v2.1/{orcid}/employment/{putCode} | Fetch an Employment
*MemberAPIV21Api* | [**view_employment_summary**](docs/MemberAPIV21Api.md#view_employment_summary) | **GET** /v2.1/{orcid}/employment/summary/{putCode} | Fetch an Employment Summary
*MemberAPIV21Api* | [**view_employments**](docs/MemberAPIV21Api.md#view_employments) | **GET** /v2.1/{orcid}/employments | Fetch all employments
*MemberAPIV21Api* | [**view_external_identifier**](docs/MemberAPIV21Api.md#view_external_identifier) | **GET** /v2.1/{orcid}/external-identifiers/{putCode} | Fetch external identifier
*MemberAPIV21Api* | [**view_external_identifiers**](docs/MemberAPIV21Api.md#view_external_identifiers) | **GET** /v2.1/{orcid}/external-identifiers | Fetch external identifiers
*MemberAPIV21Api* | [**view_funding**](docs/MemberAPIV21Api.md#view_funding) | **GET** /v2.1/{orcid}/funding/{putCode} | Fetch a Funding
*MemberAPIV21Api* | [**view_funding_summary**](docs/MemberAPIV21Api.md#view_funding_summary) | **GET** /v2.1/{orcid}/funding/summary/{putCode} | Fetch a Funding Summary
*MemberAPIV21Api* | [**view_fundings**](docs/MemberAPIV21Api.md#view_fundings) | **GET** /v2.1/{orcid}/fundings | Fetch all fundings
*MemberAPIV21Api* | [**view_group_id_record**](docs/MemberAPIV21Api.md#view_group_id_record) | **GET** /v2.1/group-id-record/{putCode} | Fetch a Group
*MemberAPIV21Api* | [**view_group_id_records**](docs/MemberAPIV21Api.md#view_group_id_records) | **GET** /v2.1/group-id-record | Fetch Groups
*MemberAPIV21Api* | [**view_keyword**](docs/MemberAPIV21Api.md#view_keyword) | **GET** /v2.1/{orcid}/keywords/{putCode} | Fetch keyword
*MemberAPIV21Api* | [**view_keywords**](docs/MemberAPIV21Api.md#view_keywords) | **GET** /v2.1/{orcid}/keywords | Fetch keywords
*MemberAPIV21Api* | [**view_other_name**](docs/MemberAPIV21Api.md#view_other_name) | **GET** /v2.1/{orcid}/other-names/{putCode} | Fetch Other name
*MemberAPIV21Api* | [**view_other_names**](docs/MemberAPIV21Api.md#view_other_names) | **GET** /v2.1/{orcid}/other-names | Fetch Other names
*MemberAPIV21Api* | [**view_peer_review**](docs/MemberAPIV21Api.md#view_peer_review) | **GET** /v2.1/{orcid}/peer-review/{putCode} | Fetch a Peer Review
*MemberAPIV21Api* | [**view_peer_review_summary**](docs/MemberAPIV21Api.md#view_peer_review_summary) | **GET** /v2.1/{orcid}/peer-review/summary/{putCode} | Fetch a Peer Review Summary
*MemberAPIV21Api* | [**view_peer_reviews**](docs/MemberAPIV21Api.md#view_peer_reviews) | **GET** /v2.1/{orcid}/peer-reviews | Fetch all peer reviews
*MemberAPIV21Api* | [**view_permission_notification**](docs/MemberAPIV21Api.md#view_permission_notification) | **GET** /v2.1/{orcid}/notification-permission/{id} | Fetch a notification by id
*MemberAPIV21Api* | [**view_person**](docs/MemberAPIV21Api.md#view_person) | **GET** /v2.1/{orcid}/person | Fetch person details
*MemberAPIV21Api* | [**view_personal_details**](docs/MemberAPIV21Api.md#view_personal_details) | **GET** /v2.1/{orcid}/personal-details | Fetch personal details for an ORCID ID
*MemberAPIV21Api* | [**view_record**](docs/MemberAPIV21Api.md#view_record) | **GET** /v2.1/{orcid}{ignore} | Fetch record details
*MemberAPIV21Api* | [**view_researcher_url**](docs/MemberAPIV21Api.md#view_researcher_url) | **GET** /v2.1/{orcid}/researcher-urls/{putCode} | Fetch one researcher url for an ORCID ID
*MemberAPIV21Api* | [**view_researcher_urls**](docs/MemberAPIV21Api.md#view_researcher_urls) | **GET** /v2.1/{orcid}/researcher-urls | Fetch all researcher urls for an ORCID ID
*MemberAPIV21Api* | [**view_specified_works**](docs/MemberAPIV21Api.md#view_specified_works) | **GET** /v2.1/{orcid}/works/{putCodes} | Fetch specified works
*MemberAPIV21Api* | [**view_work**](docs/MemberAPIV21Api.md#view_work) | **GET** /v2.1/{orcid}/work/{putCode} | Fetch a Work
*MemberAPIV21Api* | [**view_work_summary**](docs/MemberAPIV21Api.md#view_work_summary) | **GET** /v2.1/{orcid}/work/summary/{putCode} | Fetch a Work Summary
*MemberAPIV21Api* | [**view_works**](docs/MemberAPIV21Api.md#view_works) | **GET** /v2.1/{orcid}/works | Fetch all works


## Documentation For Models

 - [ActivitiesSummary](docs/ActivitiesSummary.md)
 - [Address](docs/Address.md)
 - [Amount](docs/Amount.md)
 - [AuthorizationUrl](docs/AuthorizationUrl.md)
 - [BulkElement](docs/BulkElement.md)
 - [Citation](docs/Citation.md)
 - [Contributor](docs/Contributor.md)
 - [ContributorAttributes](docs/ContributorAttributes.md)
 - [ContributorEmail](docs/ContributorEmail.md)
 - [ContributorOrcid](docs/ContributorOrcid.md)
 - [Country](docs/Country.md)
 - [CreatedDate](docs/CreatedDate.md)
 - [CreditName](docs/CreditName.md)
 - [Day](docs/Day.md)
 - [DisambiguatedOrganization](docs/DisambiguatedOrganization.md)
 - [Education](docs/Education.md)
 - [EducationSummary](docs/EducationSummary.md)
 - [Educations](docs/Educations.md)
 - [Employment](docs/Employment.md)
 - [EmploymentSummary](docs/EmploymentSummary.md)
 - [Employments](docs/Employments.md)
 - [ExternalID](docs/ExternalID.md)
 - [ExternalIDs](docs/ExternalIDs.md)
 - [Funding](docs/Funding.md)
 - [FundingContributor](docs/FundingContributor.md)
 - [FundingContributorAttributes](docs/FundingContributorAttributes.md)
 - [FundingContributors](docs/FundingContributors.md)
 - [FundingGroup](docs/FundingGroup.md)
 - [FundingSummary](docs/FundingSummary.md)
 - [FundingTitle](docs/FundingTitle.md)
 - [Fundings](docs/Fundings.md)
 - [FuzzyDate](docs/FuzzyDate.md)
 - [GroupIdRecord](docs/GroupIdRecord.md)
 - [GroupIdRecords](docs/GroupIdRecords.md)
 - [Item](docs/Item.md)
 - [Items](docs/Items.md)
 - [Keyword](docs/Keyword.md)
 - [LastModifiedDate](docs/LastModifiedDate.md)
 - [Month](docs/Month.md)
 - [Notification](docs/Notification.md)
 - [NotificationPermission](docs/NotificationPermission.md)
 - [Organization](docs/Organization.md)
 - [OrganizationAddress](docs/OrganizationAddress.md)
 - [OrganizationDefinedFundingSubType](docs/OrganizationDefinedFundingSubType.md)
 - [OtherName](docs/OtherName.md)
 - [PeerReview](docs/PeerReview.md)
 - [PeerReviewGroup](docs/PeerReviewGroup.md)
 - [PeerReviewSummary](docs/PeerReviewSummary.md)
 - [PeerReviews](docs/PeerReviews.md)
 - [PersonExternalIdentifier](docs/PersonExternalIdentifier.md)
 - [PublicationDate](docs/PublicationDate.md)
 - [ResearcherUrl](docs/ResearcherUrl.md)
 - [Source](docs/Source.md)
 - [SourceClientId](docs/SourceClientId.md)
 - [SourceName](docs/SourceName.md)
 - [SourceOrcid](docs/SourceOrcid.md)
 - [Subtitle](docs/Subtitle.md)
 - [Title](docs/Title.md)
 - [TranslatedTitle](docs/TranslatedTitle.md)
 - [Url](docs/Url.md)
 - [Work](docs/Work.md)
 - [WorkBulk](docs/WorkBulk.md)
 - [WorkContributors](docs/WorkContributors.md)
 - [WorkGroup](docs/WorkGroup.md)
 - [WorkSummary](docs/WorkSummary.md)
 - [WorkTitle](docs/WorkTitle.md)
 - [Works](docs/Works.md)
 - [Year](docs/Year.md)


## Documentation For Authorization


## orcid_auth

- **Type**: OAuth
- **Flow**: accessCode
- **Authorization URL**: https://orcid.org/oauth/authorize
- **Scopes**: 
 - **/read-limited**: Read Limited record
 - **/activities/update**: Update activities
 - **/person/update**: Update person

## orcid_two_legs

- **Type**: OAuth
- **Flow**: application
- **Authorization URL**: 
- **Scopes**: 
 - **/group-id-record/update**: Update groups
 - **/premium-notification**: Notifications
 - **/group-id-record/read**: Read groups
 - **/read-public**: Read Public record


## Author



