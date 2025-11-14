import pytest
from sqlalchemy.orm.exc import DetachedInstanceError

from src.auth.dto import CreateUserPayload, CreateOrganizationPayload
from src.auth.models import User


class TestCreateUserRepository:
    def test_get_count(self, TestUserRepository, test_users):
        count = TestUserRepository.get_count()
        
        assert count == 2

    def test_get_all(self, TestUserRepository, test_users):
        users = TestUserRepository.get_all()
        
        assert len(users) == 2
        for user in users:
            assert isinstance(user, User)
    
    def test_check_username_unique(self, TestUserRepository, test_user):
        username_unique = "test"
        username_duplicate = "test_user"
    
        assert TestUserRepository.check_username_unique(username_unique)
        assert not TestUserRepository.check_username_unique(username_duplicate)
    
    def test_check_email_unique(self, TestUserRepository, test_user):
        email_unique = "test@test.com"
        email_duplicate = "test_user@test.com"
    
        assert TestUserRepository.check_email_unique(email_unique)
        assert not TestUserRepository.check_email_unique(email_duplicate)

    def test_create_not_an_organization_member(self, TestUserRepository):
        assert TestUserRepository.get_count() == 0
    
        user = User(
            email="test@test.com",
            username="test",
            password_hash="hashed_password",  # Will be hashed in create_user_service
        )
        user = TestUserRepository.create(user, attribute_names=["organization"])
    
        assert TestUserRepository.get_count() == 1
        assert user.id is not None
        assert user.organization is None

    def test_create_without_attribute_names_does_not_select_relationships(
        self, 
        TestUserRepository,
    ):
    
        user = User(
            email="test@test.com",
            username="test",
            password_hash="hashed_password",  # Will be hashed in create_user_service
        )
        user = TestUserRepository.create(user)
    
        with pytest.raises(DetachedInstanceError):
            user.organization


    def test_create_an_organization_member(self, TestUserRepository, test_organization):
        assert TestUserRepository.get_count() == 1

        user = User(
            email="member@test.com",
            username="member",
            password_hash="hashed_password",
            organization_id=test_organization.id
        )
        user = TestUserRepository.create(user, attribute_names=["organization"])

        assert TestUserRepository.get_count() == 2
        assert user.id is not None
        assert user.organization_id == test_organization.id
        assert user.organization.id == test_organization.id
        assert user.organization.name == test_organization.name
