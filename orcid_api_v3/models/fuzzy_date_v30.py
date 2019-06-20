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
from orcid_api_v3.models.day_v30 import DayV30  # noqa: F401,E501
from orcid_api_v3.models.month_v30 import MonthV30  # noqa: F401,E501
from orcid_api_v3.models.year_v30 import YearV30  # noqa: F401,E501


class FuzzyDateV30(object):
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
        'year': 'YearV30',
        'month': 'MonthV30',
        'day': 'DayV30'
    }

    attribute_map = {
        'year': 'year',
        'month': 'month',
        'day': 'day'
    }

    def __init__(self, year=None, month=None, day=None):  # noqa: E501
        """FuzzyDateV30 - a model defined in Swagger"""  # noqa: E501
        self._year = None
        self._month = None
        self._day = None
        self.discriminator = None
        self.year = year
        if month is not None:
            self.month = month
        if day is not None:
            self.day = day

    @property
    def year(self):
        """Gets the year of this FuzzyDateV30.  # noqa: E501


        :return: The year of this FuzzyDateV30.  # noqa: E501
        :rtype: YearV30
        """
        return self._year

    @year.setter
    def year(self, year):
        """Sets the year of this FuzzyDateV30.


        :param year: The year of this FuzzyDateV30.  # noqa: E501
        :type: YearV30
        """
        if year is None:
            raise ValueError("Invalid value for `year`, must not be `None`")  # noqa: E501

        self._year = year

    @property
    def month(self):
        """Gets the month of this FuzzyDateV30.  # noqa: E501


        :return: The month of this FuzzyDateV30.  # noqa: E501
        :rtype: MonthV30
        """
        return self._month

    @month.setter
    def month(self, month):
        """Sets the month of this FuzzyDateV30.


        :param month: The month of this FuzzyDateV30.  # noqa: E501
        :type: MonthV30
        """

        self._month = month

    @property
    def day(self):
        """Gets the day of this FuzzyDateV30.  # noqa: E501


        :return: The day of this FuzzyDateV30.  # noqa: E501
        :rtype: DayV30
        """
        return self._day

    @day.setter
    def day(self, day):
        """Sets the day of this FuzzyDateV30.


        :param day: The day of this FuzzyDateV30.  # noqa: E501
        :type: DayV30
        """

        self._day = day

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
        if issubclass(FuzzyDateV30, dict):
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
        if not isinstance(other, FuzzyDateV30):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
