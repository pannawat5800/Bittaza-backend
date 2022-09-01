import * as bcrypt from 'bcrypt'
import { environment as env } from '../environments/environment'


export const encryptPassword = async (password: string): Promise<{ salt: string, hashPassword: string }> => {
    if (!password) throw new Error('Password is undefind or empty')

    const salt = await bcrypt.genSalt(env.saltRounds)
    const hashPassword = await bcrypt.hash(password, salt)
    return { salt, hashPassword }
}

export const checkPasswordIsCorrect = (password: string, hashPassword: string): boolean => {
    if (!password) throw new Error('Password is invalid')
    if (!hashPassword) throw new Error('hash password is invalid')

    return bcrypt.compareSync(password, hashPassword)
}