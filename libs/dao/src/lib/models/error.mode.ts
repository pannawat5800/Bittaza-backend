

import { HttpStatus } from "./response.model";

abstract class ErrorImpletement {
    abstract code: number;
    abstract status: HttpStatus;
    abstract error?: string;
    abstract message?: string;
}

export class ErrorBadRequest extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message: string, error?: string) {
        super();
        this.code = 400;
        this.status = HttpStatus.BAD_REQUEST
        this.error = error
        this.message = message
    }
}

export class ErrorNoAuthentication extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message: string, error?: string) {
        super();
        this.code = 401;
        this.status = HttpStatus.NON_AUTH
        this.error = error
        this.message = message
    }
}


export class ErrorForbbiden extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message: string, error?: string) {
        super();
        this.code = 403;
        this.status = HttpStatus.FORBBIDEN
        this.error = error
        this.message = message
    }
}


export class ErrorNotFound extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message: string, error?: string) {
        super();
        this.code = 404;
        this.status = HttpStatus.NOT_FOUND_RESOURCE
        this.error = error
        this.message = message
    }
}



export class ErrorResouresConflict extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message: string, error?: string) {
        super();
        this.code = 409;
        this.status = HttpStatus.RESOURCE_CONFLICT
        this.error = error
        this.message = message
    }
}

export class InternalError extends ErrorImpletement {
    code: number;
    status: HttpStatus;
    error?: string;
    message?: string;

    constructor(message?: string, error?: string) {
        super();
        this.code = 500;
        this.status = HttpStatus.NOT_FOUND_RESOURCE
        this.error = error
        this.message = message || "The system is error"
    }
}
