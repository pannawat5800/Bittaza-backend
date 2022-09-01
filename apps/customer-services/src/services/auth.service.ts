import { AuthenticationToken } from "../core/authenticationToken.core";
import { User, UserModel, ErrorBadRequest, ErrorNotFound } from '@back-end-services/dao';
import { checkPasswordIsCorrect, encryptPassword } from "../utils/password.util";
import logger from "../core/logger.core";



export default class AuthService {

    private authenticationToken: AuthenticationToken;

    constructor() {
        this.authenticationToken = new AuthenticationToken()

    }

    async signIn(email: string, password: string) {
        logger.info('start query user by email')
        const user = await UserModel.findOne({ email: email }).lean()
        if (!user) throw new ErrorNotFound("User is not found")

        logger.info('check password')
        const isCorectPassword = checkPasswordIsCorrect(password, user.password)
        if (!isCorectPassword) throw new ErrorNotFound('Username and password are invalid.')

        logger.info('generate access token and refresh')
        const accessToken = this.authenticationToken.generateToken(user)
        const refreshToken = this.authenticationToken.generateRefreshToken({ id: String(user._id) }, String(user.email))

        return { access: accessToken, refresh: refreshToken }
    }

    async signUp(data: User): Promise<void> {
        logger.info('check email is exist')
        const isEmailExiting = await UserModel.exists({ email: data.email })
        if (isEmailExiting) throw new ErrorBadRequest('Email has already existed.')

        logger.info('start encrypt password')
        const { salt, hashPassword } = await encryptPassword(data.password)

        logger.info('save new user data')
        const user = new UserModel({ ...data, salt, password: hashPassword })
        await user.save()
    }



}

