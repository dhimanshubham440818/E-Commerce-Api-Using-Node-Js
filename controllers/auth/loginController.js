import Joi from 'joi';
import { User, RefreshToken } from '../../models';
import CustomErrorHandler from '../../services/CustomErrorHandler';
import bcrypt from 'bcrypt';
import JwtService from '../../services/JwtService';
import { REFRESH_SECRET } from '../../config';

const loginController = {
    async login(req, res, next) {
        
        // Validation
        const loginSchema = Joi.object({
            email: Joi.string().email().required()
                .messages({
                    'string.email': `email must be valid email`,
                    'string.empty': `email cannot be empty`,
                    'any.required': `email is a required field`,
                }),
            password: joiPassword.string()
                .minOfSpecialCharacters(1)
                .minOfLowercase(1)
                .minOfUppercase(1)
                .minOfNumeric(1)
                .noWhiteSpaces()
                .required()
                .messages({
                    'password.minOfUppercase': 'password should contain at least {#min} uppercase character',
                    'password.minOfSpecialCharacters': 'password should contain at least {#min} special character',
                    'password.minOfLowercase': 'password should contain at least {#min} lowercase character',
                    'password.minOfNumeric': 'password should contain at least {#min} numeric character',
                    'password.noWhiteSpaces': 'password should not contain white spaces',
                    'password.required': 'password must be required',
                    'string.empty': 'password cannot be empty',
                }),
        });

        const { error } = loginSchema.validate(req.body);
        if (error) {
            return next(error);
        }

        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) {
                return next(CustomErrorHandler.wrongCredentials());
            }

            // compare the password
            const match = await bcrypt.compare(req.body.password, user.password);
            if (!match) {
                return next(CustomErrorHandler.wrongCredentials());
            }

            // Token
            const access_token = JwtService.sign({ _id: user._id, role: user.role });
            const refresh_token = JwtService.sign({ _id: user._id, role: user.role }, '1y', REFRESH_SECRET);
        
            // database whitelist
            await RefreshToken.create({ token: refresh_token });
            res.json({ access_token, refresh_token });

        } catch(err) {
            return next(err);
        }

    },
    
    async logout(req, res, next) {
        
        // validation
        const refreshSchema = Joi.object({
            refresh_token: Joi.string().required(),
        });
        const { error } = refreshSchema.validate(req.body);
        if (error) {
            return next(error);
        }

        try {
            await RefreshToken.deleteOne({ token: req.body.refresh_token });
        } catch(err) {
            return next(new Error('Something went wrong in the database'));
        }
        res.json({ status: 1 });
    }
};


export default loginController;