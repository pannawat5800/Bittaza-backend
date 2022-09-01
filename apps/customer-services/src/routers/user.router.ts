import { Router } from "express";
import { GetUser } from "../controllers/user.controller";
import AuthTokenVerifiactionMiddleware from "../middlewares/authentication.middleware";
const router = Router()

router.get('/', AuthTokenVerifiactionMiddleware, GetUser)

export default router