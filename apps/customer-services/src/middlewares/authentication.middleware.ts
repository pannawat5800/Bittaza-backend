import { AuthenticationToken } from "../core/authenticationToken.core";
import { UserSchema, ErrorNoAuthentication, Context } from '@back-end-services/dao';
import { NextFunction, Request, Response } from "express";
import { environment as env } from "../environments/environment";
import logger from "../core/logger.core";

const AuthTokenVerifiactionMiddleware = (request: Request, response: Response, next: NextFunction) => {
    const header = request.headers['authentication'] as string || "";
    const authentications = header.split(' ');

    if (
        authentications.length !== 2 ||
        authentications[0] != 'Barrer' ||
        authentications[1].trim() == ''
    ) {
        response.status(401).json(new ErrorNoAuthentication('Invalild authentication'))
        return;
    }

    const authenticationToken = new AuthenticationToken()
    const payload = authenticationToken.decodeToken<UserSchema & { token_type: string }>(authentications[1])
    logger.debug(payload)
    if (payload.token_type !== env.jwt_access) {
        response.status(401).json(new ErrorNoAuthentication('Credential is invalid.'))
        return;
    }

    request.context = new Context(String(payload._id))
    next()

}

export default AuthTokenVerifiactionMiddleware