import * as Joi from 'joi'

export const SignInSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
})

export const SignUpSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required().required(),
    firstName: Joi.string().required().required(),
    lastName: Joi.string().required().required(),
})

