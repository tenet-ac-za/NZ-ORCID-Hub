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
from swagger_client.models.biography_v30_rc2 import BiographyV30Rc2  # noqa: F401,E501
from swagger_client.models.last_modified_date_v30_rc2 import LastModifiedDateV30Rc2  # noqa: F401,E501
from swagger_client.models.name_v30_rc2 import NameV30Rc2  # noqa: F401,E501
from swagger_client.models.other_names_v30_rc2 import OtherNamesV30Rc2  # noqa: F401,E501


class PersonalDetailsV30Rc2(object):
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
        'last_modified_date': 'LastModifiedDateV30Rc2',
        'name': 'NameV30Rc2',
        'other_names': 'OtherNamesV30Rc2',
        'biography': 'BiographyV30Rc2',
        'path': 'str'
    }

    attribute_map = {
        'last_modified_date': 'last-modified-date',
        'name': 'name',
        'other_names': 'other-names',
        'biography': 'biography',
        'path': 'path'
    }

    def __init__(self, last_modified_date=None, name=None, other_names=None, biography=None, path=None):  # noqa: E501
        """PersonalDetailsV30Rc2 - a model defined in Swagger"""  # noqa: E501
        self._last_modified_date = None
        self._name = None
        self._other_names = None
        self._biography = None
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
        if path is not None:
            self.path = path

    @property
    def last_modified_date(self):
        """Gets the last_modified_date of this PersonalDetailsV30Rc2.  # noqa: E501


        :return: The last_modified_date of this PersonalDetailsV30Rc2.  # noqa: E501
        :rtype: LastModifiedDateV30Rc2
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """Sets the last_modified_date of this PersonalDetailsV30Rc2.


        :param last_modified_date: The last_modified_date of this PersonalDetailsV30Rc2.  # noqa: E501
        :type: LastModifiedDateV30Rc2
        """

        self._last_modified_date = last_modified_date

    @property
    def name(self):
        """Gets the name of this PersonalDetailsV30Rc2.  # noqa: E501


        :return: The name of this PersonalDetailsV30Rc2.  # noqa: E501
        :rtype: NameV30Rc2
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this PersonalDetailsV30Rc2.


        :param name: The name of this PersonalDetailsV30Rc2.  # noqa: E501
        :type: NameV30Rc2
        """

        self._name = name

    @property
    def other_names(self):
        """Gets the other_names of this PersonalDetailsV30Rc2.  # noqa: E501


        :return: The other_names of this PersonalDetailsV30Rc2.  # noqa: E501
        :rtype: OtherNamesV30Rc2
        """
        return self._other_names

    @other_names.setter
    def other_names(self, other_names):
        """Sets the other_names of this PersonalDetailsV30Rc2.


        :param other_names: The other_names of this PersonalDetailsV30Rc2.  # noqa: E501
        :type: OtherNamesV30Rc2
        """

        self._other_names = other_names

    @property
    def biography(self):
        """Gets the biography of this PersonalDetailsV30Rc2.  # noqa: E501


        :return: The biography of this PersonalDetailsV30Rc2.  # noqa: E501
        :rtype: BiographyV30Rc2
        """
        return self._biography

    @biography.setter
    def biography(self, biography):
        """Sets the biography of this PersonalDetailsV30Rc2.


        :param biography: The biography of this PersonalDetailsV30Rc2.  # noqa: E501
        :type: BiographyV30Rc2
        """

        self._biography = biography

    @property
    def path(self):
        """Gets the path of this PersonalDetailsV30Rc2.  # noqa: E501


        :return: The path of this PersonalDetailsV30Rc2.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this PersonalDetailsV30Rc2.


        :param path: The path of this PersonalDetailsV30Rc2.  # noqa: E501
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
        if issubclass(PersonalDetailsV30Rc2, dict):
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
        if not isinstance(other, PersonalDetailsV30Rc2):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
