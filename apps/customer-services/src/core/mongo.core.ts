import mongoose from 'mongoose'
import logger from './logger.core'
import { environment as env } from '../environments/environment';
// import env from './config.core'

const initialDatabase = async (): Promise<void> => {
    try {
        await mongoose.connect(env.dbUrl, { dbName: env.dbName });
        logger.info('Connection with mongodb is success.')
    } catch (error) {
        logger.error("connection of mongodb is failed!")
        throw error
    }
}

export default initialDatabase