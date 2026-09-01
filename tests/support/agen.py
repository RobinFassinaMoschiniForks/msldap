"""Helpers for consuming msldap's ``(result, err)`` async generators in tests."""


async def collect(agen, limit=None):
    """Drain an ``async for entry, err in ...`` generator.

    Raises on the first non-None error. Returns the list of results. If ``limit``
    is given, stops after that many results (useful to keep live tests fast on
    large directories).
    """
    out = []
    async for item, err in agen:
        if err is not None:
            raise err
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


async def first(agen):
    """Return the first result from a ``(result, err)`` generator, or None."""
    async for item, err in agen:
        if err is not None:
            raise err
        return item
    return None
