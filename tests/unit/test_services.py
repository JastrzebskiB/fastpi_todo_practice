from hashlib import sha256
from unittest.mock import MagicMock

import pytest

from src.auth.dto import CreateUserPayload
from src.auth.services import CreateUserService


class TestCreateUserService:
    def setup_method(self):
        self.mock_repo = MagicMock()
        self.payload = CreateUserPayload(
            email="test@test.com",
            username="test",
            password_hash="unhashed_password",
        )
        self.service = CreateUserService(
            repository=self.mock_repo,
        )

    def test_hash_password(self):
        expected = sha256(self.payload.password_hash.encode()).hexdigest()
        self.service.hash_password(self.payload)

        assert self.payload.password_hash == expected

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

    def test_create(self):
        self.service.create_user(self.payload)

        self.mock_repo.create.assert_called_once_with(self.payload)
