namespace AuditLog;

/// <summary>
/// Raised when the trusted anchor store (Vault) cannot be reached or refuses a write.
/// The caller must fail the whole unit of work: an audit entry without an anchor is not trustworthy.
/// </summary>
public sealed class AuditLogUnavailableException(string message, Exception? innerException = null)
    : Exception(message, innerException);
