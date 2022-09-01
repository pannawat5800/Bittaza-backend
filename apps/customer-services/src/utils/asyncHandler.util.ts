import { NextFunction, Request, Response } from "express";



type AsyncRequestHandler = (req: Request, res: Response, next: NextFunction) => Promise<any>;

export default (handler: AsyncRequestHandler) => {
    return (req: Request, res: Response, next: NextFunction) => {
        return handler(req, res, next).catch((error) => {
            next(error)
        });
    };
};