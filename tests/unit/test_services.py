from hashlib import sha256
from unittest.mock import MagicMock

import pytest

from src.auth.dto import CreateUserPayload, UserResponse
from src.auth.models import Organization, User
from src.auth.services import CreateUserService


class TestCreateUserService:
    def setup_method(self):
        self.mock_repo = MagicMock()
        self.payload = CreateUserPayload(
            email="test@test.com",
            username="test",
            password="unhashed_password",
        )
        self.mock_repo.create.return_value = User(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email=self.payload.email,
            username=self.payload.username,
        )
        self.service = CreateUserService(repository=self.mock_repo)

    def test_validate_unique_user_fields_username_duplicate(self):
        self.mock_repo.check_username_unique.return_value = False
        self.mock_repo.check_email_unique.return_value = True

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_user_fields(self.payload)

        assert str(e.value) == "The following field contains non-unique values: ['username']"

    def test_validate_unique_user_fields_email_duplicate(self):
        self.mock_repo.check_username_unique.return_value = True
        self.mock_repo.check_email_unique.return_value = False

        with pytest.raises(ValueError) as e:
            self.service.validate_unique_user_fields(self.payload)

        assert str(e.value) == "The following field contains non-unique values: ['email']"

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
        return_value = User(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email=self.payload.email,
            username=self.payload.username,
            organization_id=organization.id,
            organization=organization,
        )
        self.mock_repo.create.return_value = return_value

        result = self.service.create_user(self.payload)

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
