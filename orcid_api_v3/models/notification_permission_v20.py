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
from orcid_api_v3.models.authorization_url_v20 import AuthorizationUrlV20  # noqa: F401,E501
from orcid_api_v3.models.items_v20 import ItemsV20  # noqa: F401,E501
from orcid_api_v3.models.source_v20 import SourceV20  # noqa: F401,E501


class NotificationPermissionV20(object):
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
        'put_code': 'int',
        'notification_type': 'str',
        'authorization_url': 'AuthorizationUrlV20',
        'notification_subject': 'str',
        'notification_intro': 'str',
        'items': 'ItemsV20',
        'created_date': 'datetime',
        'sent_date': 'datetime',
        'read_date': 'datetime',
        'actioned_date': 'datetime',
        'archived_date': 'datetime',
        'source': 'SourceV20'
    }

    attribute_map = {
        'put_code': 'put-code',
        'notification_type': 'notification-type',
        'authorization_url': 'authorization-url',
        'notification_subject': 'notification-subject',
        'notification_intro': 'notification-intro',
        'items': 'items',
        'created_date': 'created-date',
        'sent_date': 'sent-date',
        'read_date': 'read-date',
        'actioned_date': 'actioned-date',
        'archived_date': 'archived-date',
        'source': 'source'
    }

    def __init__(self, put_code=None, notification_type=None, authorization_url=None, notification_subject=None, notification_intro=None, items=None, created_date=None, sent_date=None, read_date=None, actioned_date=None, archived_date=None, source=None):  # noqa: E501
        """NotificationPermissionV20 - a model defined in Swagger"""  # noqa: E501
        self._put_code = None
        self._notification_type = None
        self._authorization_url = None
        self._notification_subject = None
        self._notification_intro = None
        self._items = None
        self._created_date = None
        self._sent_date = None
        self._read_date = None
        self._actioned_date = None
        self._archived_date = None
        self._source = None
        self.discriminator = None
        if put_code is not None:
            self.put_code = put_code
        self.notification_type = notification_type
        self.authorization_url = authorization_url
        if notification_subject is not None:
            self.notification_subject = notification_subject
        if notification_intro is not None:
            self.notification_intro = notification_intro
        self.items = items
        if created_date is not None:
            self.created_date = created_date
        if sent_date is not None:
            self.sent_date = sent_date
        if read_date is not None:
            self.read_date = read_date
        if actioned_date is not None:
            self.actioned_date = actioned_date
        if archived_date is not None:
            self.archived_date = archived_date
        if source is not None:
            self.source = source

    @property
    def put_code(self):
        """Gets the put_code of this NotificationPermissionV20.  # noqa: E501


        :return: The put_code of this NotificationPermissionV20.  # noqa: E501
        :rtype: int
        """
        return self._put_code

    @put_code.setter
    def put_code(self, put_code):
        """Sets the put_code of this NotificationPermissionV20.


        :param put_code: The put_code of this NotificationPermissionV20.  # noqa: E501
        :type: int
        """

        self._put_code = put_code

    @property
    def notification_type(self):
        """Gets the notification_type of this NotificationPermissionV20.  # noqa: E501


        :return: The notification_type of this NotificationPermissionV20.  # noqa: E501
        :rtype: str
        """
        return self._notification_type

    @notification_type.setter
    def notification_type(self, notification_type):
        """Sets the notification_type of this NotificationPermissionV20.


        :param notification_type: The notification_type of this NotificationPermissionV20.  # noqa: E501
        :type: str
        """
        if notification_type is None:
            raise ValueError("Invalid value for `notification_type`, must not be `None`")  # noqa: E501
        allowed_values = ["CUSTOM", "INSTITUTIONAL_CONNECTION", "PERMISSION", "AMENDED", "SERVICE_ANNOUNCEMENT", "ADMINISTRATIVE", "TIP"]  # noqa: E501
        if notification_type not in allowed_values:
            raise ValueError(
                "Invalid value for `notification_type` ({0}), must be one of {1}"  # noqa: E501
                .format(notification_type, allowed_values)
            )

        self._notification_type = notification_type

    @property
    def authorization_url(self):
        """Gets the authorization_url of this NotificationPermissionV20.  # noqa: E501


        :return: The authorization_url of this NotificationPermissionV20.  # noqa: E501
        :rtype: AuthorizationUrlV20
        """
        return self._authorization_url

    @authorization_url.setter
    def authorization_url(self, authorization_url):
        """Sets the authorization_url of this NotificationPermissionV20.


        :param authorization_url: The authorization_url of this NotificationPermissionV20.  # noqa: E501
        :type: AuthorizationUrlV20
        """
        if authorization_url is None:
            raise ValueError("Invalid value for `authorization_url`, must not be `None`")  # noqa: E501

        self._authorization_url = authorization_url

    @property
    def notification_subject(self):
        """Gets the notification_subject of this NotificationPermissionV20.  # noqa: E501


        :return: The notification_subject of this NotificationPermissionV20.  # noqa: E501
        :rtype: str
        """
        return self._notification_subject

    @notification_subject.setter
    def notification_subject(self, notification_subject):
        """Sets the notification_subject of this NotificationPermissionV20.


        :param notification_subject: The notification_subject of this NotificationPermissionV20.  # noqa: E501
        :type: str
        """

        self._notification_subject = notification_subject

    @property
    def notification_intro(self):
        """Gets the notification_intro of this NotificationPermissionV20.  # noqa: E501


        :return: The notification_intro of this NotificationPermissionV20.  # noqa: E501
        :rtype: str
        """
        return self._notification_intro

    @notification_intro.setter
    def notification_intro(self, notification_intro):
        """Sets the notification_intro of this NotificationPermissionV20.


        :param notification_intro: The notification_intro of this NotificationPermissionV20.  # noqa: E501
        :type: str
        """

        self._notification_intro = notification_intro

    @property
    def items(self):
        """Gets the items of this NotificationPermissionV20.  # noqa: E501


        :return: The items of this NotificationPermissionV20.  # noqa: E501
        :rtype: ItemsV20
        """
        return self._items

    @items.setter
    def items(self, items):
        """Sets the items of this NotificationPermissionV20.


        :param items: The items of this NotificationPermissionV20.  # noqa: E501
        :type: ItemsV20
        """
        if items is None:
            raise ValueError("Invalid value for `items`, must not be `None`")  # noqa: E501

        self._items = items

    @property
    def created_date(self):
        """Gets the created_date of this NotificationPermissionV20.  # noqa: E501


        :return: The created_date of this NotificationPermissionV20.  # noqa: E501
        :rtype: datetime
        """
        return self._created_date

    @created_date.setter
    def created_date(self, created_date):
        """Sets the created_date of this NotificationPermissionV20.


        :param created_date: The created_date of this NotificationPermissionV20.  # noqa: E501
        :type: datetime
        """

        self._created_date = created_date

    @property
    def sent_date(self):
        """Gets the sent_date of this NotificationPermissionV20.  # noqa: E501


        :return: The sent_date of this NotificationPermissionV20.  # noqa: E501
        :rtype: datetime
        """
        return self._sent_date

    @sent_date.setter
    def sent_date(self, sent_date):
        """Sets the sent_date of this NotificationPermissionV20.


        :param sent_date: The sent_date of this NotificationPermissionV20.  # noqa: E501
        :type: datetime
        """

        self._sent_date = sent_date

    @property
    def read_date(self):
        """Gets the read_date of this NotificationPermissionV20.  # noqa: E501


        :return: The read_date of this NotificationPermissionV20.  # noqa: E501
        :rtype: datetime
        """
        return self._read_date

    @read_date.setter
    def read_date(self, read_date):
        """Sets the read_date of this NotificationPermissionV20.


        :param read_date: The read_date of this NotificationPermissionV20.  # noqa: E501
        :type: datetime
        """

        self._read_date = read_date

    @property
    def actioned_date(self):
        """Gets the actioned_date of this NotificationPermissionV20.  # noqa: E501


        :return: The actioned_date of this NotificationPermissionV20.  # noqa: E501
        :rtype: datetime
        """
        return self._actioned_date

    @actioned_date.setter
    def actioned_date(self, actioned_date):
        """Sets the actioned_date of this NotificationPermissionV20.


        :param actioned_date: The actioned_date of this NotificationPermissionV20.  # noqa: E501
        :type: datetime
        """

        self._actioned_date = actioned_date

    @property
    def archived_date(self):
        """Gets the archived_date of this NotificationPermissionV20.  # noqa: E501


        :return: The archived_date of this NotificationPermissionV20.  # noqa: E501
        :rtype: datetime
        """
        return self._archived_date

    @archived_date.setter
    def archived_date(self, archived_date):
        """Sets the archived_date of this NotificationPermissionV20.


        :param archived_date: The archived_date of this NotificationPermissionV20.  # noqa: E501
        :type: datetime
        """

        self._archived_date = archived_date

    @property
    def source(self):
        """Gets the source of this NotificationPermissionV20.  # noqa: E501


        :return: The source of this NotificationPermissionV20.  # noqa: E501
        :rtype: SourceV20
        """
        return self._source

    @source.setter
    def source(self, source):
        """Sets the source of this NotificationPermissionV20.


        :param source: The source of this NotificationPermissionV20.  # noqa: E501
        :type: SourceV20
        """

        self._source = source

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
        if issubclass(NotificationPermissionV20, dict):
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
        if not isinstance(other, NotificationPermissionV20):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
