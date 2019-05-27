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
from swagger_client.models.last_modified_date_v30 import LastModifiedDateV30  # noqa: F401,E501
from swagger_client.models.peer_review_group_v30 import PeerReviewGroupV30  # noqa: F401,E501


class PeerReviewsV30(object):
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
        'last_modified_date': 'LastModifiedDateV30',
        'group': 'list[PeerReviewGroupV30]',
        'path': 'str'
    }

    attribute_map = {
        'last_modified_date': 'last-modified-date',
        'group': 'group',
        'path': 'path'
    }

    def __init__(self, last_modified_date=None, group=None, path=None):  # noqa: E501
        """PeerReviewsV30 - a model defined in Swagger"""  # noqa: E501
        self._last_modified_date = None
        self._group = None
        self._path = None
        self.discriminator = None
        if last_modified_date is not None:
            self.last_modified_date = last_modified_date
        if group is not None:
            self.group = group
        if path is not None:
            self.path = path

    @property
    def last_modified_date(self):
        """Gets the last_modified_date of this PeerReviewsV30.  # noqa: E501


        :return: The last_modified_date of this PeerReviewsV30.  # noqa: E501
        :rtype: LastModifiedDateV30
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """Sets the last_modified_date of this PeerReviewsV30.


        :param last_modified_date: The last_modified_date of this PeerReviewsV30.  # noqa: E501
        :type: LastModifiedDateV30
        """

        self._last_modified_date = last_modified_date

    @property
    def group(self):
        """Gets the group of this PeerReviewsV30.  # noqa: E501


        :return: The group of this PeerReviewsV30.  # noqa: E501
        :rtype: list[PeerReviewGroupV30]
        """
        return self._group

    @group.setter
    def group(self, group):
        """Sets the group of this PeerReviewsV30.


        :param group: The group of this PeerReviewsV30.  # noqa: E501
        :type: list[PeerReviewGroupV30]
        """

        self._group = group

    @property
    def path(self):
        """Gets the path of this PeerReviewsV30.  # noqa: E501


        :return: The path of this PeerReviewsV30.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this PeerReviewsV30.


        :param path: The path of this PeerReviewsV30.  # noqa: E501
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
        if issubclass(PeerReviewsV30, dict):
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
        if not isinstance(other, PeerReviewsV30):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
