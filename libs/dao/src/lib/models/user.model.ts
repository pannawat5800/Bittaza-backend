import { BaseDocument } from "./db.model"

export type User = {
    email: string,
    salt: string,
    password: string,
    firstName?: string,
    lastName?: string,
}

export type UserSchema = User & BaseDocument