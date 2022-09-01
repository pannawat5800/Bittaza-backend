import mongoose from "mongoose"

export enum DBCollection {
    Users = "users",
    Coins = "coins",
}

export type BaseDocument = {
    _id: mongoose.Types.ObjectId,
    _v?: number,
    date_create?: Date,
    date_update?: Date
}



export type RedisSetProp = {
    key: string,
    value: string,
    timeType?: string,
    time?: number,
}