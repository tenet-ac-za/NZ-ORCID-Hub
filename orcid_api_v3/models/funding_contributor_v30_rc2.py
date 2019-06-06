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
from orcid_api_v3.models.contributor_email_v30_rc2 import ContributorEmailV30Rc2  # noqa: F401,E501
from orcid_api_v3.models.contributor_orcid_v30_rc2 import ContributorOrcidV30Rc2  # noqa: F401,E501
from orcid_api_v3.models.credit_name_v30_rc2 import CreditNameV30Rc2  # noqa: F401,E501
from orcid_api_v3.models.funding_contributor_attributes_v30_rc2 import FundingContributorAttributesV30Rc2  # noqa: F401,E501


class FundingContributorV30Rc2(object):
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
        'contributor_orcid': 'ContributorOrcidV30Rc2',
        'credit_name': 'CreditNameV30Rc2',
        'contributor_email': 'ContributorEmailV30Rc2',
        'contributor_attributes': 'FundingContributorAttributesV30Rc2'
    }

    attribute_map = {
        'contributor_orcid': 'contributor-orcid',
        'credit_name': 'credit-name',
        'contributor_email': 'contributor-email',
        'contributor_attributes': 'contributor-attributes'
    }

    def __init__(self, contributor_orcid=None, credit_name=None, contributor_email=None, contributor_attributes=None):  # noqa: E501
        """FundingContributorV30Rc2 - a model defined in Swagger"""  # noqa: E501
        self._contributor_orcid = None
        self._credit_name = None
        self._contributor_email = None
        self._contributor_attributes = None
        self.discriminator = None
        if contributor_orcid is not None:
            self.contributor_orcid = contributor_orcid
        if credit_name is not None:
            self.credit_name = credit_name
        if contributor_email is not None:
            self.contributor_email = contributor_email
        if contributor_attributes is not None:
            self.contributor_attributes = contributor_attributes

    @property
    def contributor_orcid(self):
        """Gets the contributor_orcid of this FundingContributorV30Rc2.  # noqa: E501


        :return: The contributor_orcid of this FundingContributorV30Rc2.  # noqa: E501
        :rtype: ContributorOrcidV30Rc2
        """
        return self._contributor_orcid

    @contributor_orcid.setter
    def contributor_orcid(self, contributor_orcid):
        """Sets the contributor_orcid of this FundingContributorV30Rc2.


        :param contributor_orcid: The contributor_orcid of this FundingContributorV30Rc2.  # noqa: E501
        :type: ContributorOrcidV30Rc2
        """

        self._contributor_orcid = contributor_orcid

    @property
    def credit_name(self):
        """Gets the credit_name of this FundingContributorV30Rc2.  # noqa: E501


        :return: The credit_name of this FundingContributorV30Rc2.  # noqa: E501
        :rtype: CreditNameV30Rc2
        """
        return self._credit_name

    @credit_name.setter
    def credit_name(self, credit_name):
        """Sets the credit_name of this FundingContributorV30Rc2.


        :param credit_name: The credit_name of this FundingContributorV30Rc2.  # noqa: E501
        :type: CreditNameV30Rc2
        """

        self._credit_name = credit_name

    @property
    def contributor_email(self):
        """Gets the contributor_email of this FundingContributorV30Rc2.  # noqa: E501


        :return: The contributor_email of this FundingContributorV30Rc2.  # noqa: E501
        :rtype: ContributorEmailV30Rc2
        """
        return self._contributor_email

    @contributor_email.setter
    def contributor_email(self, contributor_email):
        """Sets the contributor_email of this FundingContributorV30Rc2.


        :param contributor_email: The contributor_email of this FundingContributorV30Rc2.  # noqa: E501
        :type: ContributorEmailV30Rc2
        """

        self._contributor_email = contributor_email

    @property
    def contributor_attributes(self):
        """Gets the contributor_attributes of this FundingContributorV30Rc2.  # noqa: E501


        :return: The contributor_attributes of this FundingContributorV30Rc2.  # noqa: E501
        :rtype: FundingContributorAttributesV30Rc2
        """
        return self._contributor_attributes

    @contributor_attributes.setter
    def contributor_attributes(self, contributor_attributes):
        """Sets the contributor_attributes of this FundingContributorV30Rc2.


        :param contributor_attributes: The contributor_attributes of this FundingContributorV30Rc2.  # noqa: E501
        :type: FundingContributorAttributesV30Rc2
        """

        self._contributor_attributes = contributor_attributes

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
        if issubclass(FundingContributorV30Rc2, dict):
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
        if not isinstance(other, FundingContributorV30Rc2):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other