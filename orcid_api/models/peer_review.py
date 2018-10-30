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


class PeerReview(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, created_date=None, last_modified_date=None, source=None, reviewer_role=None, review_identifiers=None, review_url=None, review_type=None, review_completion_date=None, review_group_id=None, subject_external_identifier=None, subject_container_name=None, subject_type=None, subject_name=None, subject_url=None, convening_organization=None, visibility=None, put_code=None, path=None):
        """
        PeerReview - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'created_date': 'object',
            'last_modified_date': 'object',
            'source': 'object',
            'reviewer_role': 'object',
            'review_identifiers': 'object',
            'review_url': 'object',
            'review_type': 'object',
            'review_completion_date': 'object',
            'review_group_id': 'str',
            'subject_external_identifier': 'object',
            'subject_container_name': 'object',
            'subject_type': 'object',
            'subject_name': 'object',
            'subject_url': 'object',
            'convening_organization': 'object',
            'visibility': 'str',
            'put_code': 'int',
            'path': 'str'
        }

        self.attribute_map = {
            'created_date': 'created-date',
            'last_modified_date': 'last-modified-date',
            'source': 'source',
            'reviewer_role': 'reviewer-role',
            'review_identifiers': 'review-identifiers',
            'review_url': 'review-url',
            'review_type': 'review-type',
            'review_completion_date': 'review-completion-date',
            'review_group_id': 'review-group-id',
            'subject_external_identifier': 'subject-external-identifier',
            'subject_container_name': 'subject-container-name',
            'subject_type': 'subject-type',
            'subject_name': 'subject-name',
            'subject_url': 'subject-url',
            'convening_organization': 'convening-organization',
            'visibility': 'visibility',
            'put_code': 'put-code',
            'path': 'path'
        }

        self._created_date = created_date
        self._last_modified_date = last_modified_date
        self._source = source
        self._reviewer_role = reviewer_role
        self._review_identifiers = review_identifiers
        self._review_url = review_url
        self._review_type = review_type
        self._review_completion_date = review_completion_date
        self._review_group_id = review_group_id
        self._subject_external_identifier = subject_external_identifier
        self._subject_container_name = subject_container_name
        self._subject_type = subject_type
        self._subject_name = subject_name
        self._subject_url = subject_url
        self._convening_organization = convening_organization
        self._visibility = visibility
        self._put_code = put_code
        self._path = path

    @property
    def created_date(self):
        """
        Gets the created_date of this PeerReview.

        :return: The created_date of this PeerReview.
        :rtype: object
        """
        return self._created_date

    @created_date.setter
    def created_date(self, created_date):
        """
        Sets the created_date of this PeerReview.

        :param created_date: The created_date of this PeerReview.
        :type: object
        """

        self._created_date = created_date

    @property
    def last_modified_date(self):
        """
        Gets the last_modified_date of this PeerReview.

        :return: The last_modified_date of this PeerReview.
        :rtype: object
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """
        Sets the last_modified_date of this PeerReview.

        :param last_modified_date: The last_modified_date of this PeerReview.
        :type: object
        """

        self._last_modified_date = last_modified_date

    @property
    def source(self):
        """
        Gets the source of this PeerReview.

        :return: The source of this PeerReview.
        :rtype: object
        """
        return self._source

    @source.setter
    def source(self, source):
        """
        Sets the source of this PeerReview.

        :param source: The source of this PeerReview.
        :type: object
        """

        self._source = source

    @property
    def reviewer_role(self):
        """
        Gets the reviewer_role of this PeerReview.

        :return: The reviewer_role of this PeerReview.
        :rtype: object
        """
        return self._reviewer_role

    @reviewer_role.setter
    def reviewer_role(self, reviewer_role):
        """
        Sets the reviewer_role of this PeerReview.

        :param reviewer_role: The reviewer_role of this PeerReview.
        :type: object
        """

        self._reviewer_role = reviewer_role

    @property
    def review_identifiers(self):
        """
        Gets the review_identifiers of this PeerReview.

        :return: The review_identifiers of this PeerReview.
        :rtype: object
        """
        return self._review_identifiers

    @review_identifiers.setter
    def review_identifiers(self, review_identifiers):
        """
        Sets the review_identifiers of this PeerReview.

        :param review_identifiers: The review_identifiers of this PeerReview.
        :type: object
        """

        self._review_identifiers = review_identifiers

    @property
    def review_url(self):
        """
        Gets the review_url of this PeerReview.

        :return: The review_url of this PeerReview.
        :rtype: object
        """
        return self._review_url

    @review_url.setter
    def review_url(self, review_url):
        """
        Sets the review_url of this PeerReview.

        :param review_url: The review_url of this PeerReview.
        :type: object
        """

        self._review_url = review_url

    @property
    def review_type(self):
        """
        Gets the review_type of this PeerReview.

        :return: The review_type of this PeerReview.
        :rtype: object
        """
        return self._review_type

    @review_type.setter
    def review_type(self, review_type):
        """
        Sets the review_type of this PeerReview.

        :param review_type: The review_type of this PeerReview.
        :type: object
        """

        self._review_type = review_type

    @property
    def review_completion_date(self):
        """
        Gets the review_completion_date of this PeerReview.

        :return: The review_completion_date of this PeerReview.
        :rtype: object
        """
        return self._review_completion_date

    @review_completion_date.setter
    def review_completion_date(self, review_completion_date):
        """
        Sets the review_completion_date of this PeerReview.

        :param review_completion_date: The review_completion_date of this PeerReview.
        :type: object
        """

        self._review_completion_date = review_completion_date

    @property
    def review_group_id(self):
        """
        Gets the review_group_id of this PeerReview.

        :return: The review_group_id of this PeerReview.
        :rtype: str
        """
        return self._review_group_id

    @review_group_id.setter
    def review_group_id(self, review_group_id):
        """
        Sets the review_group_id of this PeerReview.

        :param review_group_id: The review_group_id of this PeerReview.
        :type: str
        """
        if review_group_id is None:
            raise ValueError("Invalid value for `review_group_id`, must not be `None`")

        self._review_group_id = review_group_id

    @property
    def subject_external_identifier(self):
        """
        Gets the subject_external_identifier of this PeerReview.

        :return: The subject_external_identifier of this PeerReview.
        :rtype: object
        """
        return self._subject_external_identifier

    @subject_external_identifier.setter
    def subject_external_identifier(self, subject_external_identifier):
        """
        Sets the subject_external_identifier of this PeerReview.

        :param subject_external_identifier: The subject_external_identifier of this PeerReview.
        :type: object
        """

        self._subject_external_identifier = subject_external_identifier

    @property
    def subject_container_name(self):
        """
        Gets the subject_container_name of this PeerReview.

        :return: The subject_container_name of this PeerReview.
        :rtype: object
        """
        return self._subject_container_name

    @subject_container_name.setter
    def subject_container_name(self, subject_container_name):
        """
        Sets the subject_container_name of this PeerReview.

        :param subject_container_name: The subject_container_name of this PeerReview.
        :type: object
        """

        self._subject_container_name = subject_container_name

    @property
    def subject_type(self):
        """
        Gets the subject_type of this PeerReview.

        :return: The subject_type of this PeerReview.
        :rtype: object
        """
        return self._subject_type

    @subject_type.setter
    def subject_type(self, subject_type):
        """
        Sets the subject_type of this PeerReview.

        :param subject_type: The subject_type of this PeerReview.
        :type: object
        """

        self._subject_type = subject_type

    @property
    def subject_name(self):
        """
        Gets the subject_name of this PeerReview.

        :return: The subject_name of this PeerReview.
        :rtype: object
        """
        return self._subject_name

    @subject_name.setter
    def subject_name(self, subject_name):
        """
        Sets the subject_name of this PeerReview.

        :param subject_name: The subject_name of this PeerReview.
        :type: object
        """

        self._subject_name = subject_name

    @property
    def subject_url(self):
        """
        Gets the subject_url of this PeerReview.

        :return: The subject_url of this PeerReview.
        :rtype: object
        """
        return self._subject_url

    @subject_url.setter
    def subject_url(self, subject_url):
        """
        Sets the subject_url of this PeerReview.

        :param subject_url: The subject_url of this PeerReview.
        :type: object
        """

        self._subject_url = subject_url

    @property
    def convening_organization(self):
        """
        Gets the convening_organization of this PeerReview.

        :return: The convening_organization of this PeerReview.
        :rtype: object
        """
        return self._convening_organization

    @convening_organization.setter
    def convening_organization(self, convening_organization):
        """
        Sets the convening_organization of this PeerReview.

        :param convening_organization: The convening_organization of this PeerReview.
        :type: object
        """
        if convening_organization is None:
            raise ValueError("Invalid value for `convening_organization`, must not be `None`")

        self._convening_organization = convening_organization

    @property
    def visibility(self):
        """
        Gets the visibility of this PeerReview.

        :return: The visibility of this PeerReview.
        :rtype: str
        """
        return self._visibility

    @visibility.setter
    def visibility(self, visibility):
        """
        Sets the visibility of this PeerReview.

        :param visibility: The visibility of this PeerReview.
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
    def put_code(self):
        """
        Gets the put_code of this PeerReview.

        :return: The put_code of this PeerReview.
        :rtype: int
        """
        return self._put_code

    @put_code.setter
    def put_code(self, put_code):
        """
        Sets the put_code of this PeerReview.

        :param put_code: The put_code of this PeerReview.
        :type: int
        """

        self._put_code = put_code

    @property
    def path(self):
        """
        Gets the path of this PeerReview.

        :return: The path of this PeerReview.
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """
        Sets the path of this PeerReview.

        :param path: The path of this PeerReview.
        :type: str
        """

        self._path = path

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
        if not isinstance(other, PeerReview):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
