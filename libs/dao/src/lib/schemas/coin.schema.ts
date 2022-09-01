import mongoose, { Schema } from 'mongoose'
import { DBCollection } from '../models/db.model'


const CoinSchema = new Schema({
    name: String,
    image: String,
    active: Boolean
})

const CoinModel = mongoose.model(DBCollection.Coins, CoinSchema)
export default CoinModel