
import { sign, verify } from 'jsonwebtoken'
// import * as fs from 'fs'
import { environment as env } from '../environments/environment'
import logger from './logger.core'

export class AuthenticationToken {
    private readonly accessSecreteKey: string
    private readonly refreshSecreteKey: string

    constructor() {
        this.accessSecreteKey = env.jwt_access_key
        this.refreshSecreteKey = env.jwt_refresh_key
        logger.debug(`access key: ${this.accessSecreteKey}`)
        logger.debug(`refresh key: ${this.refreshSecreteKey}`)
    }

    generateToken(payload: object): string {
        return sign(
            { ...payload, token_type: env.jwt_access },
            this.accessSecreteKey,
            {
                expiresIn: '1h',
                audience: env.jwt_audience,
                issuer: env.jwt_issuer,
            }
        )
    }

    decodeToken<T>(token: string): T {
        return verify(token, this.accessSecreteKey, {
            audience: env.jwt_audience,
            issuer: env.jwt_issuer,
        }) as T
    }

    generateRefreshToken(payload: object, subject: string): string {
        return sign(
            { ...payload, token_type: this.refreshSecreteKey },
            this.refreshSecreteKey,
            {
                expiresIn: '24h',
                subject: subject,
                // algorithm: this.algorithm,
                audience: env.jwt_audience,
                issuer: env.jwt_issuer,
            }
        )
    }

    decodeRefreshToken<T>(token: string): T {
        return verify(token, this.refreshSecreteKey) as T
    }

}
