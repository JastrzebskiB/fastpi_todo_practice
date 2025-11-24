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
        organization_service_mock = MagicMock()
        self.service.hash_password = lambda x: "hashed"
        result = self.service.create_user(self.payload, organization_service_mock)

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
        user_service_mock = MagicMock()
        user_service_mock.repository = user_repository_mock

        result = self.service.add_users_to_organization(
            organization_id=self.organization.id,
            payload=self.payload,
            user_service=user_service_mock,
        )

        self.mock_repo.exists_with_id.assert_called_once_with(self.organization.id)
        user_repository_mock.add_users_to_organization.assert_called_once()

    def test_create_organization_response(self):
        self.organization.owner = User(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email="owner@test.com",
            username="owner",
            organization_id=self.organization.id,
        )
        self.organization.members = [
            self.organization.owner,
            User(
                id="e9819698-eb36-45d7-a630-0cdd56346457",
                email="test_1@test.com",
                username="test_1",
                organization_id=self.organization.id,
            ),
        ]

        result = self.service.create_organization_response(self.organization, UserService())

        assert str(result.id) == "00019698-eb36-45d7-a630-0cdd56346457"
        assert result.name == "test_org"
        assert str(result.owner.id) == self.organization.owner.id
        assert result.owner.email == self.organization.owner.email
        assert result.owner.username == self.organization.owner.username
        assert len(result.members) == 2
        assert str(result.members[0].id) == self.organization.members[0].id
        assert result.members[0].email == self.organization.members[0].email
        assert result.members[0].username == self.organization.members[0].username
        assert str(result.members[1].id) == self.organization.members[1].id
        assert result.members[1].email == self.organization.members[1].email
        assert result.members[1].username == self.organization.members[1].username
