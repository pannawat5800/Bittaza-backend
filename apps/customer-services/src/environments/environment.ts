
export const environment = {
  production: false,
  port: Number(process.env.PORT) || 3333,
  dbName: process.env.DB_NAME || 'CrpytoCurrency',
  dbUrl: process.env.DB_URL || 'mongodb://localhost:27017',
  saltRounds: 10,
  // jwt_private_key: `${process.cwd()}/app/customer-services/src/assets/private.key`,
  // jwt_public_key: `${process.cwd()}/app/customer-services/src/assets/public.pem`,
  jwt_access_key: process.env.JWT_ACCESS_KEY,
  jwt_refresh_key: process.env.JWT_REFRESH_KEY,
  jwt_audience: process.env.JWT_AUDIENCE,
  jwt_issuer: process.env.JWT_ISSUER,
  jwt_refresh: process.env.JWT_REFRESH,
  jwt_access: process.env.JWT_ACCESS,
  jwt_access_expireIn: '1h'
};
