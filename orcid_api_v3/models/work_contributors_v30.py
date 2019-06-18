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
from orcid_api_v3.models.contributor_v30 import ContributorV30  # noqa: F401,E501


class WorkContributorsV30(object):
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
        'contributor': 'list[ContributorV30]'
    }

    attribute_map = {
        'contributor': 'contributor'
    }

    def __init__(self, contributor=None):  # noqa: E501
        """WorkContributorsV30 - a model defined in Swagger"""  # noqa: E501
        self._contributor = None
        self.discriminator = None
        if contributor is not None:
            self.contributor = contributor

    @property
    def contributor(self):
        """Gets the contributor of this WorkContributorsV30.  # noqa: E501


        :return: The contributor of this WorkContributorsV30.  # noqa: E501
        :rtype: list[ContributorV30]
        """
        return self._contributor

    @contributor.setter
    def contributor(self, contributor):
        """Sets the contributor of this WorkContributorsV30.


        :param contributor: The contributor of this WorkContributorsV30.  # noqa: E501
        :type: list[ContributorV30]
        """

        self._contributor = contributor

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
        if issubclass(WorkContributorsV30, dict):
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
        if not isinstance(other, WorkContributorsV30):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
