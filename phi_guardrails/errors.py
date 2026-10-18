"""Exceptions. Their messages are fixed text and never include scanned content."""


class GuardError(Exception):
    """An error the command line reports by its message."""


class RosterError(GuardError):
    """The roster or its key is missing, invalid, or could not be built."""


class ConfigError(GuardError):
    """A command was run without the setup it needs."""


class ScanError(GuardError):
    """A history scan could not read everything it was asked to read."""
