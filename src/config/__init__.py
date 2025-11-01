from .config import Settings


# TODO: Consider using get_settings with @lru_cache instead of initializing settings like now
# More info: https://fastapi.tiangolo.com/advanced/settings/#the-main-app-file
settings = Settings()
