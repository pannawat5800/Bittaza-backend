import { Router } from "express";
import AuthApi from './auth.router';
import UserApi from './user.router';
const router = Router()

router.use('/auth', AuthApi)
router.use('/users', UserApi)

export default router

