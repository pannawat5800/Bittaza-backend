import mongoose from "mongoose"


export type HistoryTransaction = {
    high: number
    low: number
    open: number
    close: number
    coin: mongoose.Types.ObjectId
}