import { ErrorBadRequest, ErrorForbbiden, ErrorNoAuthentication, ErrorNotFound, ErrorResouresConflict, InternalError } from '@back-end-services/dao';
import { NextFunction, Request, Response, } from "express"
import logger from '../core/logger.core';


export const ApiNotFoundHandler = (_: Request, response: Response) => {
    const error = new ErrorNotFound('api path is not found.')
    response.status(error.code).json(error)
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const ErrorApiHandler = (error: unknown, request: Request, response: Response, next: NextFunction): void => {
    logger.error(`api ${request.path} error: `, error)
    const isErrorImplementation = (error instanceof ErrorBadRequest) ||
        (error instanceof ErrorNoAuthentication) ||
        (error instanceof ErrorForbbiden) ||
        (error instanceof ErrorNotFound) ||
        (error instanceof ErrorResouresConflict)

    if (isErrorImplementation) {
        response.status(error.code).json(error)
    } else {
        response.status(500).json(new InternalError())
    }
}
