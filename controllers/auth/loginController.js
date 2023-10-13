import finalResponce from '../../services/finalResponce'
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
                password: Joi.string().min(3).max(30).required()
                .messages({
                    'string.empty': `password cannot be an empty field`,
                    'string.min': `password should have a minimum length of {#limit}`,
                    'any.required': `password is a required field`,
                }),
        });

        const { error } = loginSchema.validate(req.body);
        if (error) {
            return next(error);
        }

        try {
            const user = await User.findOne({ email: req.body.email });
            if (!user) {
                return next(CustomErrorHandler.wrongCredentials('wrong Credentials'));
            }

            // compare the password
            const match = await bcrypt.compare(req.body.password, user.password);
            if (!match) {
                return next(CustomErrorHandler.wrongCredentials('wrong Credentials'));
            }

            // Token
            const access_token = JwtService.sign({ _id: user._id, role: user.role });
            const refresh_token = JwtService.sign({ _id: user._id, role: user.role }, '1y', REFRESH_SECRET);
        
            // database whitelist
            await RefreshToken.create({ token: refresh_token });
            let token = {access_token , refresh_token, role:user.role , name:user.name }
            res.status(200).json(finalResponce(token));
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
        res.json({ status: true, error:false, messages:'Successfully Logout'});
    }
};


export default loginController;