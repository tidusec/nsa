import requests


class Backend:
    def __init__(self, base_url, subject_getter):
        self.subject_getter = subject_getter
        self.base_url = base_url.rstrip("/") if base_url else None

    def _build_url(self, url):
        """Combine base_url with the provided url if base_url exists"""
        if not url.startswith(("http://", "https://")):
            return f"{self.base_url}/{url.lstrip('/')}"
        return url

    def _modify_kwargs(self, **kwargs):
        headers = kwargs.get("headers", {}).copy()

        subject = self.subject_getter()
        if subject:
            headers["NSA-Subject"] = subject

        kwargs["headers"] = headers
        return kwargs

    def _call(self, func, *args, **kwargs):
        kwargs = self._modify_kwargs(**kwargs)
        return func(*args, **kwargs)

    def get(self, url, **kwargs):
        return self._call(requests.get, self._build_url(url), **kwargs)

    def post(self, url, **kwargs):
        return self._call(requests.post, self._build_url(url), **kwargs)

    def put(self, url, **kwargs):
        return self._call(requests.put, self._build_url(url), **kwargs)

    def delete(self, url, **kwargs):
        return self._call(requests.delete, self._build_url(url), **kwargs)

    def patch(self, url, **kwargs):
        return self._call(requests.patch, self._build_url(url), **kwargs)
