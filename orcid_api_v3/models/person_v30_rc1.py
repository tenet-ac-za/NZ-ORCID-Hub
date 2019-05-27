# coding: utf-8

"""
    ORCID Member

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)  # noqa: E501

    OpenAPI spec version: Latest
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""

import pprint
import re  # noqa: F401

import six
from swagger_client.models.addresses_v30_rc1 import AddressesV30Rc1  # noqa: F401,E501
from swagger_client.models.biography_v30_rc1 import BiographyV30Rc1  # noqa: F401,E501
from swagger_client.models.emails_v30_rc1 import EmailsV30Rc1  # noqa: F401,E501
from swagger_client.models.keywords_v30_rc1 import KeywordsV30Rc1  # noqa: F401,E501
from swagger_client.models.last_modified_date_v30_rc1 import LastModifiedDateV30Rc1  # noqa: F401,E501
from swagger_client.models.name_v30_rc1 import NameV30Rc1  # noqa: F401,E501
from swagger_client.models.other_names_v30_rc1 import OtherNamesV30Rc1  # noqa: F401,E501
from swagger_client.models.person_external_identifiers_v30_rc1 import PersonExternalIdentifiersV30Rc1  # noqa: F401,E501
from swagger_client.models.researcher_urls_v30_rc1 import ResearcherUrlsV30Rc1  # noqa: F401,E501


class PersonV30Rc1(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """
    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'last_modified_date': 'LastModifiedDateV30Rc1',
        'name': 'NameV30Rc1',
        'other_names': 'OtherNamesV30Rc1',
        'biography': 'BiographyV30Rc1',
        'researcher_urls': 'ResearcherUrlsV30Rc1',
        'emails': 'EmailsV30Rc1',
        'addresses': 'AddressesV30Rc1',
        'keywords': 'KeywordsV30Rc1',
        'external_identifiers': 'PersonExternalIdentifiersV30Rc1',
        'path': 'str'
    }

    attribute_map = {
        'last_modified_date': 'last-modified-date',
        'name': 'name',
        'other_names': 'other-names',
        'biography': 'biography',
        'researcher_urls': 'researcher-urls',
        'emails': 'emails',
        'addresses': 'addresses',
        'keywords': 'keywords',
        'external_identifiers': 'external-identifiers',
        'path': 'path'
    }

    def __init__(self, last_modified_date=None, name=None, other_names=None, biography=None, researcher_urls=None, emails=None, addresses=None, keywords=None, external_identifiers=None, path=None):  # noqa: E501
        """PersonV30Rc1 - a model defined in Swagger"""  # noqa: E501
        self._last_modified_date = None
        self._name = None
        self._other_names = None
        self._biography = None
        self._researcher_urls = None
        self._emails = None
        self._addresses = None
        self._keywords = None
        self._external_identifiers = None
        self._path = None
        self.discriminator = None
        if last_modified_date is not None:
            self.last_modified_date = last_modified_date
        if name is not None:
            self.name = name
        if other_names is not None:
            self.other_names = other_names
        if biography is not None:
            self.biography = biography
        if researcher_urls is not None:
            self.researcher_urls = researcher_urls
        if emails is not None:
            self.emails = emails
        if addresses is not None:
            self.addresses = addresses
        if keywords is not None:
            self.keywords = keywords
        if external_identifiers is not None:
            self.external_identifiers = external_identifiers
        if path is not None:
            self.path = path

    @property
    def last_modified_date(self):
        """Gets the last_modified_date of this PersonV30Rc1.  # noqa: E501


        :return: The last_modified_date of this PersonV30Rc1.  # noqa: E501
        :rtype: LastModifiedDateV30Rc1
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """Sets the last_modified_date of this PersonV30Rc1.


        :param last_modified_date: The last_modified_date of this PersonV30Rc1.  # noqa: E501
        :type: LastModifiedDateV30Rc1
        """

        self._last_modified_date = last_modified_date

    @property
    def name(self):
        """Gets the name of this PersonV30Rc1.  # noqa: E501


        :return: The name of this PersonV30Rc1.  # noqa: E501
        :rtype: NameV30Rc1
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this PersonV30Rc1.


        :param name: The name of this PersonV30Rc1.  # noqa: E501
        :type: NameV30Rc1
        """

        self._name = name

    @property
    def other_names(self):
        """Gets the other_names of this PersonV30Rc1.  # noqa: E501


        :return: The other_names of this PersonV30Rc1.  # noqa: E501
        :rtype: OtherNamesV30Rc1
        """
        return self._other_names

    @other_names.setter
    def other_names(self, other_names):
        """Sets the other_names of this PersonV30Rc1.


        :param other_names: The other_names of this PersonV30Rc1.  # noqa: E501
        :type: OtherNamesV30Rc1
        """

        self._other_names = other_names

    @property
    def biography(self):
        """Gets the biography of this PersonV30Rc1.  # noqa: E501


        :return: The biography of this PersonV30Rc1.  # noqa: E501
        :rtype: BiographyV30Rc1
        """
        return self._biography

    @biography.setter
    def biography(self, biography):
        """Sets the biography of this PersonV30Rc1.


        :param biography: The biography of this PersonV30Rc1.  # noqa: E501
        :type: BiographyV30Rc1
        """

        self._biography = biography

    @property
    def researcher_urls(self):
        """Gets the researcher_urls of this PersonV30Rc1.  # noqa: E501


        :return: The researcher_urls of this PersonV30Rc1.  # noqa: E501
        :rtype: ResearcherUrlsV30Rc1
        """
        return self._researcher_urls

    @researcher_urls.setter
    def researcher_urls(self, researcher_urls):
        """Sets the researcher_urls of this PersonV30Rc1.


        :param researcher_urls: The researcher_urls of this PersonV30Rc1.  # noqa: E501
        :type: ResearcherUrlsV30Rc1
        """

        self._researcher_urls = researcher_urls

    @property
    def emails(self):
        """Gets the emails of this PersonV30Rc1.  # noqa: E501


        :return: The emails of this PersonV30Rc1.  # noqa: E501
        :rtype: EmailsV30Rc1
        """
        return self._emails

    @emails.setter
    def emails(self, emails):
        """Sets the emails of this PersonV30Rc1.


        :param emails: The emails of this PersonV30Rc1.  # noqa: E501
        :type: EmailsV30Rc1
        """

        self._emails = emails

    @property
    def addresses(self):
        """Gets the addresses of this PersonV30Rc1.  # noqa: E501


        :return: The addresses of this PersonV30Rc1.  # noqa: E501
        :rtype: AddressesV30Rc1
        """
        return self._addresses

    @addresses.setter
    def addresses(self, addresses):
        """Sets the addresses of this PersonV30Rc1.


        :param addresses: The addresses of this PersonV30Rc1.  # noqa: E501
        :type: AddressesV30Rc1
        """

        self._addresses = addresses

    @property
    def keywords(self):
        """Gets the keywords of this PersonV30Rc1.  # noqa: E501


        :return: The keywords of this PersonV30Rc1.  # noqa: E501
        :rtype: KeywordsV30Rc1
        """
        return self._keywords

    @keywords.setter
    def keywords(self, keywords):
        """Sets the keywords of this PersonV30Rc1.


        :param keywords: The keywords of this PersonV30Rc1.  # noqa: E501
        :type: KeywordsV30Rc1
        """

        self._keywords = keywords

    @property
    def external_identifiers(self):
        """Gets the external_identifiers of this PersonV30Rc1.  # noqa: E501


        :return: The external_identifiers of this PersonV30Rc1.  # noqa: E501
        :rtype: PersonExternalIdentifiersV30Rc1
        """
        return self._external_identifiers

    @external_identifiers.setter
    def external_identifiers(self, external_identifiers):
        """Sets the external_identifiers of this PersonV30Rc1.


        :param external_identifiers: The external_identifiers of this PersonV30Rc1.  # noqa: E501
        :type: PersonExternalIdentifiersV30Rc1
        """

        self._external_identifiers = external_identifiers

    @property
    def path(self):
        """Gets the path of this PersonV30Rc1.  # noqa: E501


        :return: The path of this PersonV30Rc1.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this PersonV30Rc1.


        :param path: The path of this PersonV30Rc1.  # noqa: E501
        :type: str
        """

        self._path = path

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(PersonV30Rc1, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, PersonV30Rc1):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
