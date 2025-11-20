## Setup:

### Virtualenv + dependencies
```
poetry env use {path to your python3.13}
$(poetry env activate)
poetry install
```

### Config + database setup

```
cp .env.example .env  # Make changes as necessary
psql -U postgres < scripts/setup_db.sql  # drops existing fastapi_todo_dev db
alembic upgrade head
```

## Running the app

### Dev

```
fastapi dev src/main.py
```

### Prod

### Testing

```
pytest
```
