package decentralabs.blockchain.service.auth;

import org.springframework.http.HttpStatus;

public class SessionTicketException extends RuntimeException {
    private final HttpStatus status;
    private final String code;

    public SessionTicketException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }
}
