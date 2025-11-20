from hashlib import sha256
from unittest.mock import MagicMock

import pytest

from src.auth.dto import (
    CreateUserPayload, 
    CreateOrganizationPayload, 
    UserResponseFlat,
    OrganizationResponse, 
    UserResponse,
) 
from src.auth.models import Organization, User
from src.auth.services import OrganizationService, UserService


class TestUserService:
    def setup_method(self):
        self.payload = CreateUserPayload(
            email="test@test.com",
            username="test",
            password="unhashed_password",
        )
        self.user = User(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email=self.payload.email,
            username=self.payload.username,
        )
        self.mock_repo = MagicMock()
        self.mock_repo.create.return_value = self.user
        self.service = UserService(repository=self.mock_repo)

    def test_validate_unique_user_fields_username_duplicate(self):
        self.mock_repo.check_username_unique.return_value = False
        self.mock_repo.check_email_unique.return_value = True

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_user_fields(self.payload)

        assert str(e.value) == "The following field contains non-unique value: ['username']"

    def test_validate_unique_user_fields_email_duplicate(self):
        self.mock_repo.check_username_unique.return_value = True
        self.mock_repo.check_email_unique.return_value = False

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_user_fields(self.payload)

        assert str(e.value) == "The following field contains non-unique value: ['email']"

    def test_validate_unique_user_fields_username_and_email_duplicate(self):
        self.mock_repo.check_username_unique.return_value = False
        self.mock_repo.check_email_unique.return_value = False

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_user_fields(self.payload)

        assert (
            str(e.value) == "The following fields contain non-unique values: ['username', 'email']"
        )

    def test_validate_unique_user_fields_no_duplicates(self):
        self.mock_repo.check_username_unique.return_value = True
        self.mock_repo.check_email_unique.return_value = True

        # No need for assert - no exception raised means test passed
        self.service.validate_unique_user_fields(self.payload)

    def test_create_domain_user_instance(self):
        user = self.service.create_domain_user_instance(self.payload)

        assert user.email == self.payload.email
        assert user.username == self.payload.username
        # I can't be arsed to test password hashing

    # test_hash_password omitted - it would be basically testing 3rd party code

    def test_create_not_an_organization_member(self):
        self.service.hash_password = lambda x: "hashed"
        result = self.service.create_user(self.payload)

        # Assert repository.create got called with the correct arguments (i.e. that the password
        # gets hashed)
        create_argument = self.mock_repo.create._mock_call_args_list[0][0][0]
        assert isinstance(create_argument, User)
        assert create_argument.email == self.payload.email
        assert create_argument.username == self.payload.username
        assert create_argument.password_hash == "hashed"

        # Assert returned value is correct as well
        assert isinstance(result, UserResponse)
        assert result.email == self.payload.email
        assert result.username == self.payload.username
        assert result.owned_organization is None
        assert result.organization is None

    def test_create_an_organization_member(self):
        # Setup return values and mocks
        self.service.hash_password = lambda x: "hashed"
        organization = Organization(
            id="33704e66-4182-41a1-bb14-c919132c7a15",
            name="test_org"
        )
        self.payload.organization_id = organization.id

        self.user.organization_id = organization.id
        self.user.organization = organization
        self.mock_repo.create.return_value = self.user

        # passing organizatoin_service explicitly because Depends doesn't work in unit tests
        result = self.service.create_user(self.payload, organization_service=OrganizationService())

        # Assert repository.create got called with the correct arguments (i.e. that the password
        # gets hashed)
        create_argument = self.mock_repo.create._mock_call_args_list[0][0][0]
        assert isinstance(create_argument, User)
        assert create_argument.email == self.payload.email
        assert create_argument.username == self.payload.username
        assert create_argument.password_hash == "hashed"
        assert create_argument.organization_id == self.payload.organization_id

        # Assert returned value is correct as well
        assert isinstance(result, UserResponse)
        assert result.email == self.payload.email
        assert result.username == self.payload.username
        assert result.owned_organization is None
        assert str(result.organization.id) == self.payload.organization_id

    # test_create_user_response omitted, it's covered by the test_create_... tests

    def test_create_user_response_flat(self):
        self.user.password_hash = "hashed_password"

        result = self.service.create_user_response_flat(self.user)

        assert str(result.id) == self.user.id
        assert result.email == self.user.email
        assert result.username == self.user.username


class TestOrganizationService:
    def setup_method(self):
        self.mock_repo = MagicMock()
        self.payload = CreateOrganizationPayload(
            name="test_org",
            owner_id="d8719698-eb36-45d7-a630-0cdd56346457",
            member_ids=[],
        )
        self.organization = Organization(
            id="00019698-eb36-45d7-a630-0cdd56346457",
            name=self.payload.name,
            owner_id=self.payload.owner_id,
            members=[]
        )
        self.mock_repo.create.return_value = self.organization
        self.service = OrganizationService(repository=self.mock_repo)

    def test_validate_unique_organization_fields_name_duplicate(self):
        self.mock_repo.check_name_unique.return_value = False

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_organization_fields(self.payload)

        assert str(e.value) == "The following field contains non-unique value: ['name']"

    def test_validate_unique_organization_fields_no_duplicates(self):
        self.mock_repo.check_name_unique.return_value = True

        # No need for assert - no exception raised means test passed
        self.service.validate_unique_organization_fields(self.payload)

    def test_create_domain_user_instance(self):
        organization = self.service.create_domain_organization_instance(self.payload)

        assert organization.name == self.payload.name
        assert organization.owner_id == self.payload.owner_id
        assert not organization.members  # handled in a later stage

    def test_add_users_to_organization(self):
        self.payload.member_ids = [
            "e9819698-eb36-45d7-a630-0cdd56346457", 
            "f0919698-eb36-45d7-a630-0cdd56346457",
        ]

        user_repository_mock = MagicMock()
        user_repository_mock.add_users_to_organization.return_value = [
            User(
                id="d8719698-eb36-45d7-a630-0cdd56346457",
                username="owner",
                email="owner@test.com",
                organization_id=self.organization.id,
            ),
            User(
                id="e9819698-eb36-45d7-a630-0cdd56346457",
                username="test_1",
                email="test_1@test.com",
                organization_id=self.organization.id,
            ),
            User(
                id="f0919698-eb36-45d7-a630-0cdd56346457",
                username="test_2",
                email="test_2@test.com",
                organization_id=self.organization.id,
            ),
        ]

        user_service_mock = MagicMock()
        user_service_mock.create_user_response_flat.side_effect = [
            UserResponseFlat(
                id="d8719698-eb36-45d7-a630-0cdd56346457",
                username="owner",
                email="owner@test.com",
            ),  # owner as owner
            UserResponseFlat(
                id="d8719698-eb36-45d7-a630-0cdd56346457",
                username="owner",
                email="owner@test.com",
            ),  # owner as first member
            UserResponseFlat(
                id="e9819698-eb36-45d7-a630-0cdd56346457",
                username="test_1",
                email="test_1@test.com",
            ),
            UserResponseFlat(
                id="f0919698-eb36-45d7-a630-0cdd56346457",
                username="test_2",
                email="test_2@test.com",
            )
        ] 
        user_service_mock.repository = user_repository_mock

        result = self.service.add_users_to_organization(
            organization_id=self.organization.id,
            payload=self.payload,
            user_service=user_service_mock,
        )

        self.mock_repo.exists_with_id.assert_called_once_with(self.organization.id)
        assert isinstance(result[0], UserResponseFlat)
        assert result[0].username == "owner"
        assert isinstance(result[1][0], UserResponseFlat)
        assert isinstance(result[1][1], UserResponseFlat)
        assert isinstance(result[1][2], UserResponseFlat)
        assert result[1][0].username == "owner"
        assert result[1][1].username == "test_1"
        assert result[1][2].username == "test_2"

    def test_create_organization_response(self):
        owner = UserResponseFlat(
                id="d8719698-eb36-45d7-a630-0cdd56346457",
                username="owner",
                email="owner@test.com",
                organization_id=self.organization.id,
            )
        members = [
            UserResponseFlat(
                id="e9819698-eb36-45d7-a630-0cdd56346457",
                username="test_1",
                email="test_1@test.com",
                organization_id=self.organization.id,
            ),
            UserResponseFlat(
                id="f0919698-eb36-45d7-a630-0cdd56346457",
                username="test_2",
                email="test_2@test.com",
                organization_id=self.organization.id,
            ),
        ]

        result = self.service.create_organization_response(self.mock_repo.create(), owner, members)

        assert str(result.id) == "00019698-eb36-45d7-a630-0cdd56346457"
        assert result.name == "test_org"
        assert result.owner == owner
        assert result.members == members
