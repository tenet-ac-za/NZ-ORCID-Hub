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


class AuthorizationUrlV30Rc1(object):
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
        'uri': 'str',
        'path': 'str',
        'host': 'str'
    }

    attribute_map = {
        'uri': 'uri',
        'path': 'path',
        'host': 'host'
    }

    def __init__(self, uri=None, path=None, host=None):  # noqa: E501
        """AuthorizationUrlV30Rc1 - a model defined in Swagger"""  # noqa: E501
        self._uri = None
        self._path = None
        self._host = None
        self.discriminator = None
        self.uri = uri
        self.path = path
        self.host = host

    @property
    def uri(self):
        """Gets the uri of this AuthorizationUrlV30Rc1.  # noqa: E501


        :return: The uri of this AuthorizationUrlV30Rc1.  # noqa: E501
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """Sets the uri of this AuthorizationUrlV30Rc1.


        :param uri: The uri of this AuthorizationUrlV30Rc1.  # noqa: E501
        :type: str
        """
        if uri is None:
            raise ValueError("Invalid value for `uri`, must not be `None`")  # noqa: E501

        self._uri = uri

    @property
    def path(self):
        """Gets the path of this AuthorizationUrlV30Rc1.  # noqa: E501


        :return: The path of this AuthorizationUrlV30Rc1.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this AuthorizationUrlV30Rc1.


        :param path: The path of this AuthorizationUrlV30Rc1.  # noqa: E501
        :type: str
        """
        if path is None:
            raise ValueError("Invalid value for `path`, must not be `None`")  # noqa: E501

        self._path = path

    @property
    def host(self):
        """Gets the host of this AuthorizationUrlV30Rc1.  # noqa: E501


        :return: The host of this AuthorizationUrlV30Rc1.  # noqa: E501
        :rtype: str
        """
        return self._host

    @host.setter
    def host(self, host):
        """Sets the host of this AuthorizationUrlV30Rc1.


        :param host: The host of this AuthorizationUrlV30Rc1.  # noqa: E501
        :type: str
        """
        if host is None:
            raise ValueError("Invalid value for `host`, must not be `None`")  # noqa: E501

        self._host = host

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
        if issubclass(AuthorizationUrlV30Rc1, dict):
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
        if not isinstance(other, AuthorizationUrlV30Rc1):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
