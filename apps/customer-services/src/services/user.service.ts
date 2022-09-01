import { ErrorNotFound, User, UserSchema, UserModel } from '@back-end-services/dao';

export default class UserService {

    async getUser(uid: string): Promise<UserSchema> {
        const user = await UserModel.findById(uid)
        if (!user) throw new ErrorNotFound('User is not found.')
        return user
    }

    async updateUser(uid: string, data: User): Promise<UserSchema> {
        const user = await UserModel.findByIdAndUpdate(uid, data, { new: true })
        if (!user) throw new ErrorNotFound('User is not found.')
        return user
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async uploadImage(uid: string, file: Buffer) {
        console.log('data')
    }

}