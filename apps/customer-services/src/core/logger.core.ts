import { createLogger, format, transports } from 'winston'

const logger = createLogger({
    level: 'debug',
    defaultMeta: { service: 'customer-services' },
    format: format.combine(
        format.colorize(),
        format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        format.printf((info) => `${info.timestamp} ${info.level}: ${typeof info.message === 'object' ? JSON.stringify(info.message, null, 4) : info.message}`)
    ),
    transports: [new transports.Console()]
});

export default logger