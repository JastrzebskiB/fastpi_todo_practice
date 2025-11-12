from src.auth.dto import CreateUserPayload
from src.auth.models import User


class TestCreateUserRepository:
    def test_get_all(self, TestUserRepository, test_users):
        users = TestUserRepository.get_all()
        
        assert len(users) == 2
        for user in users:
            assert isinstance(user, User)

    def test_create(self, TestUserRepository):
        # TODO: Is this assertion needed?
        users = TestUserRepository.get_all()
        assert not users
    
        payload = CreateUserPayload(
            email="test@test.com",
            username="test",
            password_hash="hashed_password",  # Will be hashed in create_user_service
        )
        user = TestUserRepository.create(payload)
    
        users = TestUserRepository.get_all()
        assert len(users) == 1
    
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
