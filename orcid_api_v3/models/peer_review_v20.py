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
from orcid_api_v3.models.created_date_v20 import CreatedDateV20  # noqa: F401,E501
from orcid_api_v3.models.external_i_ds_v20 import ExternalIDsV20  # noqa: F401,E501
from orcid_api_v3.models.external_idv20 import ExternalIDV20  # noqa: F401,E501
from orcid_api_v3.models.fuzzy_date_v20 import FuzzyDateV20  # noqa: F401,E501
from orcid_api_v3.models.last_modified_date_v20 import LastModifiedDateV20  # noqa: F401,E501
from orcid_api_v3.models.organization_v20 import OrganizationV20  # noqa: F401,E501
from orcid_api_v3.models.source_v20 import SourceV20  # noqa: F401,E501
from orcid_api_v3.models.title_v20 import TitleV20  # noqa: F401,E501
from orcid_api_v3.models.url_v20 import UrlV20  # noqa: F401,E501
from orcid_api_v3.models.work_title_v20 import WorkTitleV20  # noqa: F401,E501


class PeerReviewV20(object):
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
        'created_date': 'CreatedDateV20',
        'last_modified_date': 'LastModifiedDateV20',
        'source': 'SourceV20',
        'reviewer_role': 'str',
        'review_identifiers': 'ExternalIDsV20',
        'review_url': 'UrlV20',
        'review_type': 'str',
        'review_completion_date': 'FuzzyDateV20',
        'review_group_id': 'str',
        'subject_external_identifier': 'ExternalIDV20',
        'subject_container_name': 'TitleV20',
        'subject_type': 'str',
        'subject_name': 'WorkTitleV20',
        'subject_url': 'UrlV20',
        'convening_organization': 'OrganizationV20',
        'visibility': 'str',
        'put_code': 'int',
        'path': 'str'
    }

    attribute_map = {
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

    def __init__(self, created_date=None, last_modified_date=None, source=None, reviewer_role=None, review_identifiers=None, review_url=None, review_type=None, review_completion_date=None, review_group_id=None, subject_external_identifier=None, subject_container_name=None, subject_type=None, subject_name=None, subject_url=None, convening_organization=None, visibility=None, put_code=None, path=None):  # noqa: E501
        """PeerReviewV20 - a model defined in Swagger"""  # noqa: E501
        self._created_date = None
        self._last_modified_date = None
        self._source = None
        self._reviewer_role = None
        self._review_identifiers = None
        self._review_url = None
        self._review_type = None
        self._review_completion_date = None
        self._review_group_id = None
        self._subject_external_identifier = None
        self._subject_container_name = None
        self._subject_type = None
        self._subject_name = None
        self._subject_url = None
        self._convening_organization = None
        self._visibility = None
        self._put_code = None
        self._path = None
        self.discriminator = None
        if created_date is not None:
            self.created_date = created_date
        if last_modified_date is not None:
            self.last_modified_date = last_modified_date
        if source is not None:
            self.source = source
        if reviewer_role is not None:
            self.reviewer_role = reviewer_role
        if review_identifiers is not None:
            self.review_identifiers = review_identifiers
        if review_url is not None:
            self.review_url = review_url
        if review_type is not None:
            self.review_type = review_type
        if review_completion_date is not None:
            self.review_completion_date = review_completion_date
        self.review_group_id = review_group_id
        if subject_external_identifier is not None:
            self.subject_external_identifier = subject_external_identifier
        if subject_container_name is not None:
            self.subject_container_name = subject_container_name
        if subject_type is not None:
            self.subject_type = subject_type
        if subject_name is not None:
            self.subject_name = subject_name
        if subject_url is not None:
            self.subject_url = subject_url
        self.convening_organization = convening_organization
        if visibility is not None:
            self.visibility = visibility
        if put_code is not None:
            self.put_code = put_code
        if path is not None:
            self.path = path

    @property
    def created_date(self):
        """Gets the created_date of this PeerReviewV20.  # noqa: E501


        :return: The created_date of this PeerReviewV20.  # noqa: E501
        :rtype: CreatedDateV20
        """
        return self._created_date

    @created_date.setter
    def created_date(self, created_date):
        """Sets the created_date of this PeerReviewV20.


        :param created_date: The created_date of this PeerReviewV20.  # noqa: E501
        :type: CreatedDateV20
        """

        self._created_date = created_date

    @property
    def last_modified_date(self):
        """Gets the last_modified_date of this PeerReviewV20.  # noqa: E501


        :return: The last_modified_date of this PeerReviewV20.  # noqa: E501
        :rtype: LastModifiedDateV20
        """
        return self._last_modified_date

    @last_modified_date.setter
    def last_modified_date(self, last_modified_date):
        """Sets the last_modified_date of this PeerReviewV20.


        :param last_modified_date: The last_modified_date of this PeerReviewV20.  # noqa: E501
        :type: LastModifiedDateV20
        """

        self._last_modified_date = last_modified_date

    @property
    def source(self):
        """Gets the source of this PeerReviewV20.  # noqa: E501


        :return: The source of this PeerReviewV20.  # noqa: E501
        :rtype: SourceV20
        """
        return self._source

    @source.setter
    def source(self, source):
        """Sets the source of this PeerReviewV20.


        :param source: The source of this PeerReviewV20.  # noqa: E501
        :type: SourceV20
        """

        self._source = source

    @property
    def reviewer_role(self):
        """Gets the reviewer_role of this PeerReviewV20.  # noqa: E501


        :return: The reviewer_role of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._reviewer_role

    @reviewer_role.setter
    def reviewer_role(self, reviewer_role):
        """Sets the reviewer_role of this PeerReviewV20.


        :param reviewer_role: The reviewer_role of this PeerReviewV20.  # noqa: E501
        :type: str
        """
        allowed_values = ["REVIEWER", "EDITOR", "MEMBER", "CHAIR", "ORGANIZER"]  # noqa: E501
        if reviewer_role not in allowed_values:
            raise ValueError(
                "Invalid value for `reviewer_role` ({0}), must be one of {1}"  # noqa: E501
                .format(reviewer_role, allowed_values)
            )

        self._reviewer_role = reviewer_role

    @property
    def review_identifiers(self):
        """Gets the review_identifiers of this PeerReviewV20.  # noqa: E501


        :return: The review_identifiers of this PeerReviewV20.  # noqa: E501
        :rtype: ExternalIDsV20
        """
        return self._review_identifiers

    @review_identifiers.setter
    def review_identifiers(self, review_identifiers):
        """Sets the review_identifiers of this PeerReviewV20.


        :param review_identifiers: The review_identifiers of this PeerReviewV20.  # noqa: E501
        :type: ExternalIDsV20
        """

        self._review_identifiers = review_identifiers

    @property
    def review_url(self):
        """Gets the review_url of this PeerReviewV20.  # noqa: E501


        :return: The review_url of this PeerReviewV20.  # noqa: E501
        :rtype: UrlV20
        """
        return self._review_url

    @review_url.setter
    def review_url(self, review_url):
        """Sets the review_url of this PeerReviewV20.


        :param review_url: The review_url of this PeerReviewV20.  # noqa: E501
        :type: UrlV20
        """

        self._review_url = review_url

    @property
    def review_type(self):
        """Gets the review_type of this PeerReviewV20.  # noqa: E501


        :return: The review_type of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._review_type

    @review_type.setter
    def review_type(self, review_type):
        """Sets the review_type of this PeerReviewV20.


        :param review_type: The review_type of this PeerReviewV20.  # noqa: E501
        :type: str
        """
        allowed_values = ["REVIEW", "EVALUATION"]  # noqa: E501
        if review_type not in allowed_values:
            raise ValueError(
                "Invalid value for `review_type` ({0}), must be one of {1}"  # noqa: E501
                .format(review_type, allowed_values)
            )

        self._review_type = review_type

    @property
    def review_completion_date(self):
        """Gets the review_completion_date of this PeerReviewV20.  # noqa: E501


        :return: The review_completion_date of this PeerReviewV20.  # noqa: E501
        :rtype: FuzzyDateV20
        """
        return self._review_completion_date

    @review_completion_date.setter
    def review_completion_date(self, review_completion_date):
        """Sets the review_completion_date of this PeerReviewV20.


        :param review_completion_date: The review_completion_date of this PeerReviewV20.  # noqa: E501
        :type: FuzzyDateV20
        """

        self._review_completion_date = review_completion_date

    @property
    def review_group_id(self):
        """Gets the review_group_id of this PeerReviewV20.  # noqa: E501


        :return: The review_group_id of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._review_group_id

    @review_group_id.setter
    def review_group_id(self, review_group_id):
        """Sets the review_group_id of this PeerReviewV20.


        :param review_group_id: The review_group_id of this PeerReviewV20.  # noqa: E501
        :type: str
        """
        if review_group_id is None:
            raise ValueError("Invalid value for `review_group_id`, must not be `None`")  # noqa: E501

        self._review_group_id = review_group_id

    @property
    def subject_external_identifier(self):
        """Gets the subject_external_identifier of this PeerReviewV20.  # noqa: E501


        :return: The subject_external_identifier of this PeerReviewV20.  # noqa: E501
        :rtype: ExternalIDV20
        """
        return self._subject_external_identifier

    @subject_external_identifier.setter
    def subject_external_identifier(self, subject_external_identifier):
        """Sets the subject_external_identifier of this PeerReviewV20.


        :param subject_external_identifier: The subject_external_identifier of this PeerReviewV20.  # noqa: E501
        :type: ExternalIDV20
        """

        self._subject_external_identifier = subject_external_identifier

    @property
    def subject_container_name(self):
        """Gets the subject_container_name of this PeerReviewV20.  # noqa: E501


        :return: The subject_container_name of this PeerReviewV20.  # noqa: E501
        :rtype: TitleV20
        """
        return self._subject_container_name

    @subject_container_name.setter
    def subject_container_name(self, subject_container_name):
        """Sets the subject_container_name of this PeerReviewV20.


        :param subject_container_name: The subject_container_name of this PeerReviewV20.  # noqa: E501
        :type: TitleV20
        """

        self._subject_container_name = subject_container_name

    @property
    def subject_type(self):
        """Gets the subject_type of this PeerReviewV20.  # noqa: E501


        :return: The subject_type of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._subject_type

    @subject_type.setter
    def subject_type(self, subject_type):
        """Sets the subject_type of this PeerReviewV20.


        :param subject_type: The subject_type of this PeerReviewV20.  # noqa: E501
        :type: str
        """
        allowed_values = ["ARTISTIC_PERFORMANCE", "BOOK_CHAPTER", "BOOK_REVIEW", "BOOK", "CONFERENCE_ABSTRACT", "CONFERENCE_PAPER", "CONFERENCE_POSTER", "DATA_SET", "DICTIONARY_ENTRY", "DISCLOSURE", "DISSERTATION", "EDITED_BOOK", "ENCYCLOPEDIA_ENTRY", "INVENTION", "JOURNAL_ARTICLE", "JOURNAL_ISSUE", "LECTURE_SPEECH", "LICENSE", "MAGAZINE_ARTICLE", "MANUAL", "NEWSLETTER_ARTICLE", "NEWSPAPER_ARTICLE", "ONLINE_RESOURCE", "OTHER", "PATENT", "REGISTERED_COPYRIGHT", "REPORT", "RESEARCH_TECHNIQUE", "RESEARCH_TOOL", "SPIN_OFF_COMPANY", "STANDARDS_AND_POLICY", "SUPERVISED_STUDENT_PUBLICATION", "TECHNICAL_STANDARD", "TEST", "TRADEMARK", "TRANSLATION", "WEBSITE", "WORKING_PAPER", "UNDEFINED"]  # noqa: E501
        if subject_type not in allowed_values:
            raise ValueError(
                "Invalid value for `subject_type` ({0}), must be one of {1}"  # noqa: E501
                .format(subject_type, allowed_values)
            )

        self._subject_type = subject_type

    @property
    def subject_name(self):
        """Gets the subject_name of this PeerReviewV20.  # noqa: E501


        :return: The subject_name of this PeerReviewV20.  # noqa: E501
        :rtype: WorkTitleV20
        """
        return self._subject_name

    @subject_name.setter
    def subject_name(self, subject_name):
        """Sets the subject_name of this PeerReviewV20.


        :param subject_name: The subject_name of this PeerReviewV20.  # noqa: E501
        :type: WorkTitleV20
        """

        self._subject_name = subject_name

    @property
    def subject_url(self):
        """Gets the subject_url of this PeerReviewV20.  # noqa: E501


        :return: The subject_url of this PeerReviewV20.  # noqa: E501
        :rtype: UrlV20
        """
        return self._subject_url

    @subject_url.setter
    def subject_url(self, subject_url):
        """Sets the subject_url of this PeerReviewV20.


        :param subject_url: The subject_url of this PeerReviewV20.  # noqa: E501
        :type: UrlV20
        """

        self._subject_url = subject_url

    @property
    def convening_organization(self):
        """Gets the convening_organization of this PeerReviewV20.  # noqa: E501


        :return: The convening_organization of this PeerReviewV20.  # noqa: E501
        :rtype: OrganizationV20
        """
        return self._convening_organization

    @convening_organization.setter
    def convening_organization(self, convening_organization):
        """Sets the convening_organization of this PeerReviewV20.


        :param convening_organization: The convening_organization of this PeerReviewV20.  # noqa: E501
        :type: OrganizationV20
        """
        if convening_organization is None:
            raise ValueError("Invalid value for `convening_organization`, must not be `None`")  # noqa: E501

        self._convening_organization = convening_organization

    @property
    def visibility(self):
        """Gets the visibility of this PeerReviewV20.  # noqa: E501


        :return: The visibility of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._visibility

    @visibility.setter
    def visibility(self, visibility):
        """Sets the visibility of this PeerReviewV20.


        :param visibility: The visibility of this PeerReviewV20.  # noqa: E501
        :type: str
        """
        allowed_values = ["LIMITED", "REGISTERED_ONLY", "PUBLIC", "PRIVATE"]  # noqa: E501
        if visibility not in allowed_values:
            raise ValueError(
                "Invalid value for `visibility` ({0}), must be one of {1}"  # noqa: E501
                .format(visibility, allowed_values)
            )

        self._visibility = visibility

    @property
    def put_code(self):
        """Gets the put_code of this PeerReviewV20.  # noqa: E501


        :return: The put_code of this PeerReviewV20.  # noqa: E501
        :rtype: int
        """
        return self._put_code

    @put_code.setter
    def put_code(self, put_code):
        """Sets the put_code of this PeerReviewV20.


        :param put_code: The put_code of this PeerReviewV20.  # noqa: E501
        :type: int
        """

        self._put_code = put_code

    @property
    def path(self):
        """Gets the path of this PeerReviewV20.  # noqa: E501


        :return: The path of this PeerReviewV20.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this PeerReviewV20.


        :param path: The path of this PeerReviewV20.  # noqa: E501
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
        if issubclass(PeerReviewV20, dict):
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
        if not isinstance(other, PeerReviewV20):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
