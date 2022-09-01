/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/customer-services/src/controllers/auth.controller.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SignUp = exports.SignIn = void 0;
const tslib_1 = __webpack_require__("tslib");
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
const asyncHandler_util_1 = __webpack_require__("./apps/customer-services/src/utils/asyncHandler.util.ts");
const auth_validator_1 = __webpack_require__("./apps/customer-services/src/validators/auth.validator.ts");
const auth_service_1 = __webpack_require__("./apps/customer-services/src/services/auth.service.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
exports.SignIn = (0, asyncHandler_util_1.default)((request, response) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const { error } = auth_validator_1.SignInSchema.validate(request.body);
    if (error)
        throw new dao_1.ErrorBadRequest(error.message);
    const { email, password } = request.body;
    const authenService = new auth_service_1.default();
    const result = yield authenService.signIn(email, password);
    response.json(result);
}));
exports.SignUp = (0, asyncHandler_util_1.default)((request, response) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const { error } = auth_validator_1.SignUpSchema.validate(request.body);
    logger_core_1.default.error(error);
    if (error)
        throw new dao_1.ErrorBadRequest(error.message);
    const authenService = new auth_service_1.default();
    yield authenService.signUp(request.body);
    response.status(204).send();
}));


/***/ }),

/***/ "./apps/customer-services/src/controllers/error.controller.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ErrorApiHandler = exports.ApiNotFoundHandler = void 0;
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
const ApiNotFoundHandler = (_, response) => {
    const error = new dao_1.ErrorNotFound('api path is not found.');
    response.status(error.code).json(error);
};
exports.ApiNotFoundHandler = ApiNotFoundHandler;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const ErrorApiHandler = (error, request, response, next) => {
    logger_core_1.default.error(`api ${request.path} error: `, error);
    const isErrorImplementation = (error instanceof dao_1.ErrorBadRequest) ||
        (error instanceof dao_1.ErrorNoAuthentication) ||
        (error instanceof dao_1.ErrorForbbiden) ||
        (error instanceof dao_1.ErrorNotFound) ||
        (error instanceof dao_1.ErrorResouresConflict);
    if (isErrorImplementation) {
        response.status(error.code).json(error);
    }
    else {
        response.status(500).json(new dao_1.InternalError());
    }
};
exports.ErrorApiHandler = ErrorApiHandler;


/***/ }),

/***/ "./apps/customer-services/src/controllers/user.controller.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUser = exports.GetUser = void 0;
const tslib_1 = __webpack_require__("tslib");
const asyncHandler_util_1 = __webpack_require__("./apps/customer-services/src/utils/asyncHandler.util.ts");
const mongoose_1 = __webpack_require__("mongoose");
const user_service_1 = __webpack_require__("./apps/customer-services/src/services/user.service.ts");
const auth_validator_1 = __webpack_require__("./apps/customer-services/src/validators/auth.validator.ts");
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
exports.GetUser = (0, asyncHandler_util_1.default)((request, response) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const uid = request.context.getUid();
    const userService = new user_service_1.default();
    const user = yield userService.getUser(uid);
    response.json(user);
}));
exports.UpdateUser = (0, asyncHandler_util_1.default)((request, response) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    const id = request.params.id;
    const body = request.body;
    if (!id || !(0, mongoose_1.isValidObjectId)(id))
        throw new dao_1.ErrorBadRequest('id is invalid');
    const { error } = auth_validator_1.SignUpSchema.validate(body);
    if (error)
        throw new dao_1.ErrorBadRequest(error.message);
    const userService = new user_service_1.default();
    const user = yield userService.updateUser(id, body);
    response.json(user);
}));


/***/ }),

/***/ "./apps/customer-services/src/core/authenticationToken.core.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthenticationToken = void 0;
const jsonwebtoken_1 = __webpack_require__("jsonwebtoken");
// import * as fs from 'fs'
const environment_1 = __webpack_require__("./apps/customer-services/src/environments/environment.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
class AuthenticationToken {
    constructor() {
        this.accessSecreteKey = environment_1.environment.jwt_access_key;
        this.refreshSecreteKey = environment_1.environment.jwt_refresh_key;
        logger_core_1.default.debug(`access key: ${this.accessSecreteKey}`);
        logger_core_1.default.debug(`refresh key: ${this.refreshSecreteKey}`);
    }
    generateToken(payload) {
        return (0, jsonwebtoken_1.sign)(Object.assign(Object.assign({}, payload), { token_type: environment_1.environment.jwt_access }), this.accessSecreteKey, {
            expiresIn: '1h',
            audience: environment_1.environment.jwt_audience,
            issuer: environment_1.environment.jwt_issuer,
        });
    }
    decodeToken(token) {
        return (0, jsonwebtoken_1.verify)(token, this.accessSecreteKey, {
            audience: environment_1.environment.jwt_audience,
            issuer: environment_1.environment.jwt_issuer,
        });
    }
    generateRefreshToken(payload, subject) {
        return (0, jsonwebtoken_1.sign)(Object.assign(Object.assign({}, payload), { token_type: this.refreshSecreteKey }), this.refreshSecreteKey, {
            expiresIn: '24h',
            subject: subject,
            // algorithm: this.algorithm,
            audience: environment_1.environment.jwt_audience,
            issuer: environment_1.environment.jwt_issuer,
        });
    }
    decodeRefreshToken(token) {
        return (0, jsonwebtoken_1.verify)(token, this.refreshSecreteKey);
    }
}
exports.AuthenticationToken = AuthenticationToken;


/***/ }),

/***/ "./apps/customer-services/src/core/logger.core.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const winston_1 = __webpack_require__("winston");
const logger = (0, winston_1.createLogger)({
    level: 'debug',
    defaultMeta: { service: 'customer-services' },
    format: winston_1.format.combine(winston_1.format.colorize(), winston_1.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss'
    }), winston_1.format.printf((info) => `${info.timestamp} ${info.level}: ${typeof info.message === 'object' ? JSON.stringify(info.message, null, 4) : info.message}`)),
    transports: [new winston_1.transports.Console()]
});
exports["default"] = logger;


/***/ }),

/***/ "./apps/customer-services/src/core/mongo.core.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
const mongoose_1 = __webpack_require__("mongoose");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
const environment_1 = __webpack_require__("./apps/customer-services/src/environments/environment.ts");
// import env from './config.core'
const initialDatabase = () => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    try {
        yield mongoose_1.default.connect(environment_1.environment.dbUrl, { dbName: environment_1.environment.dbName });
        logger_core_1.default.info('Connection with mongodb is success.');
    }
    catch (error) {
        logger_core_1.default.error("connection of mongodb is failed!");
        throw error;
    }
});
exports["default"] = initialDatabase;


/***/ }),

/***/ "./apps/customer-services/src/environments/environment.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.environment = void 0;
exports.environment = {
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


/***/ }),

/***/ "./apps/customer-services/src/middlewares/authentication.middleware.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const authenticationToken_core_1 = __webpack_require__("./apps/customer-services/src/core/authenticationToken.core.ts");
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
const environment_1 = __webpack_require__("./apps/customer-services/src/environments/environment.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
const AuthTokenVerifiactionMiddleware = (request, response, next) => {
    const header = request.headers['authentication'] || "";
    const authentications = header.split(' ');
    if (authentications.length !== 2 ||
        authentications[0] != 'Barrer' ||
        authentications[1].trim() == '') {
        response.status(401).json(new dao_1.ErrorNoAuthentication('Invalild authentication'));
        return;
    }
    const authenticationToken = new authenticationToken_core_1.AuthenticationToken();
    const payload = authenticationToken.decodeToken(authentications[1]);
    logger_core_1.default.debug(payload);
    if (payload.token_type !== environment_1.environment.jwt_access) {
        response.status(401).json(new dao_1.ErrorNoAuthentication('Credential is invalid.'));
        return;
    }
    request.context = new dao_1.Context(String(payload._id));
    next();
};
exports["default"] = AuthTokenVerifiactionMiddleware;


/***/ }),

/***/ "./apps/customer-services/src/routers/auth.router.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const express_1 = __webpack_require__("express");
const auth_controller_1 = __webpack_require__("./apps/customer-services/src/controllers/auth.controller.ts");
const router = (0, express_1.Router)();
router.post('/sign-in', auth_controller_1.SignIn);
router.post('/sign-up', auth_controller_1.SignUp);
exports["default"] = router;


/***/ }),

/***/ "./apps/customer-services/src/routers/index.router.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const express_1 = __webpack_require__("express");
const auth_router_1 = __webpack_require__("./apps/customer-services/src/routers/auth.router.ts");
const user_router_1 = __webpack_require__("./apps/customer-services/src/routers/user.router.ts");
const router = (0, express_1.Router)();
router.use('/auth', auth_router_1.default);
router.use('/users', user_router_1.default);
exports["default"] = router;


/***/ }),

/***/ "./apps/customer-services/src/routers/user.router.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const express_1 = __webpack_require__("express");
const user_controller_1 = __webpack_require__("./apps/customer-services/src/controllers/user.controller.ts");
const authentication_middleware_1 = __webpack_require__("./apps/customer-services/src/middlewares/authentication.middleware.ts");
const router = (0, express_1.Router)();
router.get('/', authentication_middleware_1.default, user_controller_1.GetUser);
exports["default"] = router;


/***/ }),

/***/ "./apps/customer-services/src/services/auth.service.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
const authenticationToken_core_1 = __webpack_require__("./apps/customer-services/src/core/authenticationToken.core.ts");
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
const password_util_1 = __webpack_require__("./apps/customer-services/src/utils/password.util.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
class AuthService {
    constructor() {
        this.authenticationToken = new authenticationToken_core_1.AuthenticationToken();
    }
    signIn(email, password) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            logger_core_1.default.info('start query user by email');
            const user = yield dao_1.UserModel.findOne({ email: email }).lean();
            if (!user)
                throw new dao_1.ErrorNotFound("User is not found");
            logger_core_1.default.info('check password');
            const isCorectPassword = (0, password_util_1.checkPasswordIsCorrect)(password, user.password);
            if (!isCorectPassword)
                throw new dao_1.ErrorNotFound('Username and password are invalid.');
            logger_core_1.default.info('generate access token and refresh');
            const accessToken = this.authenticationToken.generateToken(user);
            const refreshToken = this.authenticationToken.generateRefreshToken({ id: String(user._id) }, String(user.email));
            return { access: accessToken, refresh: refreshToken };
        });
    }
    signUp(data) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            logger_core_1.default.info('check email is exist');
            const isEmailExiting = yield dao_1.UserModel.exists({ email: data.email });
            if (isEmailExiting)
                throw new dao_1.ErrorBadRequest('Email has already existed.');
            logger_core_1.default.info('start encrypt password');
            const { salt, hashPassword } = yield (0, password_util_1.encryptPassword)(data.password);
            logger_core_1.default.info('save new user data');
            const user = new dao_1.UserModel(Object.assign(Object.assign({}, data), { salt, password: hashPassword }));
            yield user.save();
        });
    }
}
exports["default"] = AuthService;


/***/ }),

/***/ "./apps/customer-services/src/services/user.service.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
const dao_1 = __webpack_require__("./libs/dao/src/index.ts");
class UserService {
    getUser(uid) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const user = yield dao_1.UserModel.findById(uid);
            if (!user)
                throw new dao_1.ErrorNotFound('User is not found.');
            return user;
        });
    }
    updateUser(uid, data) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const user = yield dao_1.UserModel.findByIdAndUpdate(uid, data, { new: true });
            if (!user)
                throw new dao_1.ErrorNotFound('User is not found.');
            return user;
        });
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    uploadImage(uid, file) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            console.log('data');
        });
    }
}
exports["default"] = UserService;


/***/ }),

/***/ "./apps/customer-services/src/utils/asyncHandler.util.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports["default"] = (handler) => {
    return (req, res, next) => {
        return handler(req, res, next).catch((error) => {
            next(error);
        });
    };
};


/***/ }),

/***/ "./apps/customer-services/src/utils/password.util.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.checkPasswordIsCorrect = exports.encryptPassword = void 0;
const tslib_1 = __webpack_require__("tslib");
const bcrypt = __webpack_require__("bcrypt");
const environment_1 = __webpack_require__("./apps/customer-services/src/environments/environment.ts");
const encryptPassword = (password) => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    if (!password)
        throw new Error('Password is undefind or empty');
    const salt = yield bcrypt.genSalt(environment_1.environment.saltRounds);
    const hashPassword = yield bcrypt.hash(password, salt);
    return { salt, hashPassword };
});
exports.encryptPassword = encryptPassword;
const checkPasswordIsCorrect = (password, hashPassword) => {
    if (!password)
        throw new Error('Password is invalid');
    if (!hashPassword)
        throw new Error('hash password is invalid');
    return bcrypt.compareSync(password, hashPassword);
};
exports.checkPasswordIsCorrect = checkPasswordIsCorrect;


/***/ }),

/***/ "./apps/customer-services/src/validators/auth.validator.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SignUpSchema = exports.SignInSchema = void 0;
const Joi = __webpack_require__("joi");
exports.SignInSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});
exports.SignUpSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required().required(),
    firstName: Joi.string().required().required(),
    lastName: Joi.string().required().required(),
});


/***/ }),

/***/ "./libs/dao/src/index.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/db.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/error.mode.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/history.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/instrument.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/response.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/user.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/models/core.model.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/schemas/coin.schema.ts"), exports);
tslib_1.__exportStar(__webpack_require__("./libs/dao/src/lib/schemas/user.schema.ts"), exports);


/***/ }),

/***/ "./libs/dao/src/lib/models/core.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Context = void 0;
class Context {
    constructor(uid) {
        this.uid = uid;
    }
    getUid() {
        return this.uid;
    }
}
exports.Context = Context;


/***/ }),

/***/ "./libs/dao/src/lib/models/db.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DBCollection = void 0;
var DBCollection;
(function (DBCollection) {
    DBCollection["Users"] = "users";
    DBCollection["Coins"] = "coins";
})(DBCollection = exports.DBCollection || (exports.DBCollection = {}));


/***/ }),

/***/ "./libs/dao/src/lib/models/error.mode.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.InternalError = exports.ErrorResouresConflict = exports.ErrorNotFound = exports.ErrorForbbiden = exports.ErrorNoAuthentication = exports.ErrorBadRequest = void 0;
const response_model_1 = __webpack_require__("./libs/dao/src/lib/models/response.model.ts");
class ErrorImpletement {
}
class ErrorBadRequest extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 400;
        this.status = response_model_1.HttpStatus.BAD_REQUEST;
        this.error = error;
        this.message = message;
    }
}
exports.ErrorBadRequest = ErrorBadRequest;
class ErrorNoAuthentication extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 401;
        this.status = response_model_1.HttpStatus.NON_AUTH;
        this.error = error;
        this.message = message;
    }
}
exports.ErrorNoAuthentication = ErrorNoAuthentication;
class ErrorForbbiden extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 403;
        this.status = response_model_1.HttpStatus.FORBBIDEN;
        this.error = error;
        this.message = message;
    }
}
exports.ErrorForbbiden = ErrorForbbiden;
class ErrorNotFound extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 404;
        this.status = response_model_1.HttpStatus.NOT_FOUND_RESOURCE;
        this.error = error;
        this.message = message;
    }
}
exports.ErrorNotFound = ErrorNotFound;
class ErrorResouresConflict extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 409;
        this.status = response_model_1.HttpStatus.RESOURCE_CONFLICT;
        this.error = error;
        this.message = message;
    }
}
exports.ErrorResouresConflict = ErrorResouresConflict;
class InternalError extends ErrorImpletement {
    constructor(message, error) {
        super();
        this.code = 500;
        this.status = response_model_1.HttpStatus.NOT_FOUND_RESOURCE;
        this.error = error;
        this.message = message || "The system is error";
    }
}
exports.InternalError = InternalError;


/***/ }),

/***/ "./libs/dao/src/lib/models/history.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./libs/dao/src/lib/models/instrument.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./libs/dao/src/lib/models/response.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpStatus = void 0;
var HttpStatus;
(function (HttpStatus) {
    HttpStatus["SUCCESS"] = "Success";
    HttpStatus["BAD_REQUEST"] = "Bad_Request";
    HttpStatus["FORBBIDEN"] = "Forbbiden";
    HttpStatus["NOT_FOUND_API"] = "Not_Found_Api";
    HttpStatus["NOT_FOUND_RESOURCE"] = "Not_Founed_Resource";
    HttpStatus["RESOURCE_CONFLICT"] = "Resource_Conflict";
    HttpStatus["INTERNAL_ERROR"] = "Internal_Error";
    HttpStatus["NON_AUTH"] = "Non_Authenticatoin";
})(HttpStatus = exports.HttpStatus || (exports.HttpStatus = {}));


/***/ }),

/***/ "./libs/dao/src/lib/models/user.model.ts":
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./libs/dao/src/lib/schemas/coin.schema.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const mongoose_1 = __webpack_require__("mongoose");
const db_model_1 = __webpack_require__("./libs/dao/src/lib/models/db.model.ts");
const CoinSchema = new mongoose_1.Schema({
    name: String,
    image: String,
    active: Boolean
});
const CoinModel = mongoose_1.default.model(db_model_1.DBCollection.Coins, CoinSchema);
exports["default"] = CoinModel;


/***/ }),

/***/ "./libs/dao/src/lib/schemas/user.schema.ts":
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserModel = void 0;
const mongoose_1 = __webpack_require__("mongoose");
const db_model_1 = __webpack_require__("./libs/dao/src/lib/models/db.model.ts");
const UserSchema = new mongoose_1.Schema({
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
});
exports.UserModel = mongoose_1.default.model(db_model_1.DBCollection.Users, UserSchema);


/***/ }),

/***/ "bcrypt":
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "cors":
/***/ ((module) => {

module.exports = require("cors");

/***/ }),

/***/ "dotenv/config":
/***/ ((module) => {

module.exports = require("dotenv/config");

/***/ }),

/***/ "express":
/***/ ((module) => {

module.exports = require("express");

/***/ }),

/***/ "helmet":
/***/ ((module) => {

module.exports = require("helmet");

/***/ }),

/***/ "joi":
/***/ ((module) => {

module.exports = require("joi");

/***/ }),

/***/ "jsonwebtoken":
/***/ ((module) => {

module.exports = require("jsonwebtoken");

/***/ }),

/***/ "mongoose":
/***/ ((module) => {

module.exports = require("mongoose");

/***/ }),

/***/ "tslib":
/***/ ((module) => {

module.exports = require("tslib");

/***/ }),

/***/ "winston":
/***/ ((module) => {

module.exports = require("winston");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

/**
 * This is not a production server yet!
 * This is only a minimal backend to get started.
 */
Object.defineProperty(exports, "__esModule", ({ value: true }));
const tslib_1 = __webpack_require__("tslib");
__webpack_require__("dotenv/config");
const express = __webpack_require__("express");
const cors = __webpack_require__("cors");
const helmet_1 = __webpack_require__("helmet");
const mongo_core_1 = __webpack_require__("./apps/customer-services/src/core/mongo.core.ts");
const logger_core_1 = __webpack_require__("./apps/customer-services/src/core/logger.core.ts");
const index_router_1 = __webpack_require__("./apps/customer-services/src/routers/index.router.ts");
const error_controller_1 = __webpack_require__("./apps/customer-services/src/controllers/error.controller.ts");
const app = express();
app.use(cors());
app.use((0, helmet_1.default)());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use('/api', index_router_1.default);
app.use(error_controller_1.ErrorApiHandler);
app.use('*', error_controller_1.ApiNotFoundHandler);
const port = process.env.PORT || 3333;
const Bootstrap = () => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
    try {
        yield (0, mongo_core_1.default)();
        app.listen(port, () => logger_core_1.default.info(`Listening at http://localhost:${port}/api`));
    }
    catch (error) {
        logger_core_1.default.error(`server is error: ${error}`);
    }
});
Bootstrap();
exports["default"] = app;

})();

var __webpack_export_target__ = exports;
for(var i in __webpack_exports__) __webpack_export_target__[i] = __webpack_exports__[i];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;
//# sourceMappingURL=main.js.map