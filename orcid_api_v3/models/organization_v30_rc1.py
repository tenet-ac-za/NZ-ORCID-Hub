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
from orcid_api_v3.models.disambiguated_organization_v30_rc1 import DisambiguatedOrganizationV30Rc1  # noqa: F401,E501
from orcid_api_v3.models.organization_address_v30_rc1 import OrganizationAddressV30Rc1  # noqa: F401,E501


class OrganizationV30Rc1(object):
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
        'name': 'str',
        'address': 'OrganizationAddressV30Rc1',
        'disambiguated_organization': 'DisambiguatedOrganizationV30Rc1'
    }

    attribute_map = {
        'name': 'name',
        'address': 'address',
        'disambiguated_organization': 'disambiguated-organization'
    }

    def __init__(self, name=None, address=None, disambiguated_organization=None):  # noqa: E501
        """OrganizationV30Rc1 - a model defined in Swagger"""  # noqa: E501
        self._name = None
        self._address = None
        self._disambiguated_organization = None
        self.discriminator = None
        self.name = name
        self.address = address
        if disambiguated_organization is not None:
            self.disambiguated_organization = disambiguated_organization

    @property
    def name(self):
        """Gets the name of this OrganizationV30Rc1.  # noqa: E501


        :return: The name of this OrganizationV30Rc1.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this OrganizationV30Rc1.


        :param name: The name of this OrganizationV30Rc1.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501

        self._name = name

    @property
    def address(self):
        """Gets the address of this OrganizationV30Rc1.  # noqa: E501


        :return: The address of this OrganizationV30Rc1.  # noqa: E501
        :rtype: OrganizationAddressV30Rc1
        """
        return self._address

    @address.setter
    def address(self, address):
        """Sets the address of this OrganizationV30Rc1.


        :param address: The address of this OrganizationV30Rc1.  # noqa: E501
        :type: OrganizationAddressV30Rc1
        """
        if address is None:
            raise ValueError("Invalid value for `address`, must not be `None`")  # noqa: E501

        self._address = address

    @property
    def disambiguated_organization(self):
        """Gets the disambiguated_organization of this OrganizationV30Rc1.  # noqa: E501


        :return: The disambiguated_organization of this OrganizationV30Rc1.  # noqa: E501
        :rtype: DisambiguatedOrganizationV30Rc1
        """
        return self._disambiguated_organization

    @disambiguated_organization.setter
    def disambiguated_organization(self, disambiguated_organization):
        """Sets the disambiguated_organization of this OrganizationV30Rc1.


        :param disambiguated_organization: The disambiguated_organization of this OrganizationV30Rc1.  # noqa: E501
        :type: DisambiguatedOrganizationV30Rc1
        """

        self._disambiguated_organization = disambiguated_organization

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
        if issubclass(OrganizationV30Rc1, dict):
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
        if not isinstance(other, OrganizationV30Rc1):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
