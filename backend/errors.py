"""Errors a caller can show to a user without a stack trace."""


class CodeSentinelError(Exception):
    """Base error for expected analysis failures."""


class InvalidRepositoryURL(CodeSentinelError):
    """The input is not a public GitHub repository root URL."""


class RepositoryAccessError(CodeSentinelError):
    """The repository could not be cloned."""


class RepositoryTooLarge(CodeSentinelError):
    """The clone is larger than the configured safety limit."""


class AnalysisError(CodeSentinelError):
    """The local tree could not be analyzed."""
