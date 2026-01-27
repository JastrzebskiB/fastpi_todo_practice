from .dto import CreateColumnPayload

DEFAULT_COLUMNS = [
    CreateColumnPayload(name="Backlog", order=0),
    CreateColumnPayload(name="Blocked", order=1),
    CreateColumnPayload(name="In Progress", order=2),
    CreateColumnPayload(name="In Review", order=3),
    CreateColumnPayload(name="Done", order=4, is_terminal=True),
]
