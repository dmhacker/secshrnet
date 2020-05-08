from expiringdict import ExpiringDict

HOST_REFRESH_SECONDS = 1800
HOST_TTL_SECONDS = 3600


class Server:

    def __init__(self):
        self.hosts = ExpiringDict(max_len=1e10,
                                  max_age_seconds=HOST_TTL_SECONDS)
