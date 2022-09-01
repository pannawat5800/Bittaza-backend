/**
 * This is not a production server yet!
 * This is only a minimal backend to get started.
 */

import 'dotenv/config'
import * as express from 'express';
import * as cors from 'cors';
import helmet from 'helmet';
import initialDatabase from './core/mongo.core';
import logger from './core/logger.core';
import ApplicationApi from './routers/index.router'
import { ApiNotFoundHandler, ErrorApiHandler } from './controllers/error.controller';
import { Context } from 'libs/dao/src/index'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      context: Context
    }
  }
}

const app = express();

app.use(cors())
app.use(helmet())
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/api', ApplicationApi)
app.use(ErrorApiHandler)
app.use('*', ApiNotFoundHandler)


const port = process.env.PORT || 3333
const Bootstrap = async (): Promise<void> => {
  try {
    await initialDatabase()
    app.listen(port, () => logger.info(`Listening at http://localhost:${port}/api`))
  } catch (error) {
    logger.error(`server is error: ${error}`)
  }
}

Bootstrap()

export default app