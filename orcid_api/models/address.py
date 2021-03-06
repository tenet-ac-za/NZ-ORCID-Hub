# coding: utf-8

"""
    ORCID Member

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

    OpenAPI spec version: Latest
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from pprint import pformat
from six import iteritems
import re


class Address(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, created_date=None, last_modified_date=None, source=None, country=None, visibility=None, path=None, put_code=None, display_index=None):
        """
        Address - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'created_date': 'CreatedDate',
            'last_modified_date': 'LastModifiedDate',
            'source': 'Source',
            'country': 'Country',
            'visibility': 'str',
            'path': 'str',
            'put_code': 'int',
            'display_index': 'int'
        }

        self.attribute_map = {
            'created_date': 'created-date',
            'last_modified_date': 'last-modified-date',
            'source': 'source',
            'country': 'country',
            'visibility': 'visibility',
            'path': 'path',
            'put_code': 'put-code',
            'display_index': 'display-index'
        }

        self._created_date = created_date
        self._last_modified_date = last_modified_date
        self._source = source
        self._country = country
        self._visibility = visibility
        self._path = path
        self._put_code = put_code
        self._display_index = display_index

    @property
    def created_date(self):
        """
        Gets the created_date of this Address.

        :return: The created_date of this Address.
        :rtype: CreatedDate
        """
        return self._created_date

    @created_date.setter
    def created_date(self, created_date):
        """
        Sets the created_date of this Address.

        :param created_date: The created_date of this Address.
        :type: CreatedDate
        """

        self._created_date = created_date

    @property
    def last_modified_date(self):
        """
        Gets the last_modified_date of this Address.

        :return: The last_modified_date of this Address.
        :rtype: LastModifiedDate
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """
        Sets the last_modified_date of this Address.

        :param last_modified_date: The last_modified_date of this Address.
        :type: LastModifiedDate
        """

        self._last_modified_date = last_modified_date

    @property
    def source(self):
        """
        Gets the source of this Address.

        :return: The source of this Address.
        :rtype: Source
        """
        return self._source

    @source.setter
    def source(self, source):
        """
        Sets the source of this Address.

        :param source: The source of this Address.
        :type: Source
        """

        self._source = source

    @property
    def country(self):
        """
        Gets the country of this Address.

        :return: The country of this Address.
        :rtype: Country
        """
        return self._country

    @country.setter
    def country(self, country):
        """
        Sets the country of this Address.

        :param country: The country of this Address.
        :type: Country
        """
        if country is None:
            raise ValueError("Invalid value for `country`, must not be `None`")

        self._country = country

    @property
    def visibility(self):
        """
        Gets the visibility of this Address.

        :return: The visibility of this Address.
        :rtype: str
        """
        return self._visibility

    @visibility.setter
    def visibility(self, visibility):
        """
        Sets the visibility of this Address.

        :param visibility: The visibility of this Address.
        :type: str
        """
        allowed_values = ["LIMITED", "REGISTERED_ONLY", "PUBLIC", "PRIVATE"]
        if visibility not in allowed_values:
            raise ValueError(
                "Invalid value for `visibility` ({0}), must be one of {1}"
                .format(visibility, allowed_values)
            )

        self._visibility = visibility

    @property
    def path(self):
        """
        Gets the path of this Address.

        :return: The path of this Address.
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """
        Sets the path of this Address.

        :param path: The path of this Address.
        :type: str
        """

        self._path = path

    @property
    def put_code(self):
        """
        Gets the put_code of this Address.

        :return: The put_code of this Address.
        :rtype: int
        """
        return self._put_code

    @put_code.setter
    def put_code(self, put_code):
        """
        Sets the put_code of this Address.

        :param put_code: The put_code of this Address.
        :type: int
        """

        self._put_code = put_code

    @property
    def display_index(self):
        """
        Gets the display_index of this Address.

        :return: The display_index of this Address.
        :rtype: int
        """
        return self._display_index

    @display_index.setter
    def display_index(self, display_index):
        """
        Sets the display_index of this Address.

        :param display_index: The display_index of this Address.
        :type: int
        """

        self._display_index = display_index

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
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

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        if not isinstance(other, Address):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
