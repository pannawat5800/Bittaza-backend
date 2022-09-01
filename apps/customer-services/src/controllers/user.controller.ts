import asyncHandler from "../utils/asyncHandler.util";
import { isValidObjectId } from "mongoose";
import { Request, Response } from "express";
import UserService from "../services/user.service";
import { SignUpSchema } from "../validators/auth.validator";
import { ErrorBadRequest } from '@back-end-services/dao';

export const GetUser = asyncHandler(async (request: Request, response: Response) => {
    const uid = request.context.getUid()

    const userService = new UserService()
    const user = await userService.getUser(uid)

    response.json(user)
})

export const UpdateUser = asyncHandler(async (request: Request, response: Response) => {
    const id = request.params.id
    const body = request.body

    if (!id || !isValidObjectId(id)) throw new ErrorBadRequest('id is invalid')

    const { error } = SignUpSchema.validate(body)
    if (error) throw new ErrorBadRequest(error.message)

    const userService = new UserService()
    const user = await userService.updateUser(id, body)

    response.json(user)
})



