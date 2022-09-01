import { ErrorBadRequest } from '@back-end-services/dao';
import asyncHandler from "../utils/asyncHandler.util";
import { SignInSchema, SignUpSchema } from "../validators/auth.validator"
import { Request, Response } from "express";
import AuthService from "../services/auth.service";
import logger from '../core/logger.core';

export const SignIn = asyncHandler(async (request: Request, response: Response) => {
    const { error } = SignInSchema.validate(request.body)
    if (error) throw new ErrorBadRequest(error.message)

    const { email, password } = request.body

    const authenService = new AuthService()
    const result = await authenService.signIn(email, password)

    response.json(result)
})

export const SignUp = asyncHandler(async (request: Request, response: Response) => {
    const { error } = SignUpSchema.validate(request.body)
    logger.error(error)
    if (error) throw new ErrorBadRequest(error.message)

    const authenService = new AuthService()
    await authenService.signUp(request.body)

    response.status(204).send()
})
