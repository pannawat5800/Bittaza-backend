import { Request, Response } from "express"
import asyncHandler from "../utils/asyncHandler.util";

export const GetList = asyncHandler(async (request: Request, response: Response) => {
    const { sortBy } = request.query
    response.send(sortBy)
})


