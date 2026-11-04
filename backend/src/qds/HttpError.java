package qds;

/** An error that maps straight onto an HTTP status and a {"detail": ...} body. */
final class HttpError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    final int status;

    HttpError(int status, String detail) {
        super(detail);
        this.status = status;
    }
}
