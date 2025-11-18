import pytest
from sqlalchemy.orm.exc import DetachedInstanceError

from src.auth.dto import CreateUserPayload, CreateOrganizationPayload
from src.auth.models import Organization, User


class TestUserRepository:
    def test_get_count(self, test_user_repository, test_users):
        count = test_user_repository.get_count()
        
        assert count == 2

    def test_get_all(self, test_user_repository, test_users):
        users = test_user_repository.get_all()
        
        assert len(users) == 2
        for user in users:
            assert isinstance(user, User)
    
    def test_check_username_unique(self, test_user_repository, test_user):
        username_unique = "test"
        username_duplicate = "test_user"
    
        assert test_user_repository.check_username_unique(username_unique)
        assert not test_user_repository.check_username_unique(username_duplicate)
    
    def test_check_email_unique(self, test_user_repository, test_user):
        email_unique = "test@test.com"
        email_duplicate = "test_user@test.com"
    
        assert test_user_repository.check_email_unique(email_unique)
        assert not test_user_repository.check_email_unique(email_duplicate)

    def test_create_not_an_organization_member(self, test_user_repository):
        assert test_user_repository.get_count() == 0
    
        user = User(
            email="test@test.com",
            username="test",
            password_hash="hashed_password",  # Will be hashed in create_user_service
        )
        user = test_user_repository.create(user, attribute_names=["organization"])
    
        assert test_user_repository.get_count() == 1
        assert user.id is not None
        assert user.organization is None

    def test_create_without_attribute_names_does_not_select_relationships(
        self, 
        test_user_repository,
    ):
        user = User(
            email="test@test.com",
            username="test",
            password_hash="hashed_password",  # Will be hashed in create_user_service
        )
        user = test_user_repository.create(user)
    
        with pytest.raises(DetachedInstanceError):
            user.organization

    def test_create_an_organization_member(self, test_user_repository, test_organization):
        assert test_user_repository.get_count() == 1

        user = User(
            email="member@test.com",
            username="member",
            password_hash="hashed_password",
            organization_id=test_organization.id
        )
        user = test_user_repository.create(user, attribute_names=["organization"])

        assert test_user_repository.get_count() == 2
        assert user.id is not None
        assert user.organization_id == test_organization.id
        assert user.organization.id == test_organization.id
        assert user.organization.name == test_organization.name

    def test_add_users_to_organization(self, test_user_repository, test_organization, test_users):
        member_ids = [user.id for user in test_users]
        response = test_user_repository.add_users_to_organization(test_organization.id, member_ids)

        for user in response:
            assert user.organization_id == test_organization.id


class TestOrganizationRepository:
    def test_get_count(self, test_organization_repository, test_organization):
        count = test_organization_repository.get_count()
        
        assert count == 1

    def test_get_all(self, test_organization_repository, test_organization):
        organizations = test_organization_repository.get_all()
        
        assert len(organizations) == 1
        assert isinstance(organizations[0], Organization)
    
    def test_check_name_unique(self, test_organization_repository, test_organization):
        name_unique = "test"
        name_duplicate = "test_org"
    
        assert test_organization_repository.check_name_unique(name_unique)
        assert not test_organization_repository.check_name_unique(name_duplicate)

    def test_create_organization(
        self, 
        test_organization_repository, 
        test_user_repository,  
        test_user,
    ):
        # TODO: Clean this up, this is clunky as fuck but we want to test things out 
        # We should have a fixture for an "saved to database" user for usecases like this probably
        user = test_user_repository.create(test_user)
    
        organization = Organization(
            name="test_org",
            owner_id=user.id,
            members=[]
        )

        organization = test_organization_repository.create(
            organization, attribute_names=["owner", "members"]
        )

        assert organization.id is not None
        assert organization.name == "test_org"
        assert organization.owner.id == user.id
        assert organization.owner.email == user.email
        assert organization.owner.username == user.username
