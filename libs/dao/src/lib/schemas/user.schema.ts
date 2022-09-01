import { UserSchema } from '../models/user.model'
import mongoose, { Schema } from 'mongoose'
import { DBCollection } from '../models/db.model'

const UserSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    salt: {
        type: String,
        require: true,
    },
    firstName: String,
    lastName: String,
    image: {
        type: String,
        default: ''
    },
})

export const UserModel = mongoose.model<UserSchema>(DBCollection.Users, UserSchema)