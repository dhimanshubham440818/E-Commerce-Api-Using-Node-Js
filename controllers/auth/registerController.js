import finalResponce from '../../services/finalResponce'
import Joi from 'joi';
import { User, RefreshToken } from '../../models';
import bcrypt from 'bcrypt';
import JwtService from '../../services/JwtService';
import CustomErrorHandler from '../../services/CustomErrorHandler';
import { REFRESH_SECRET } from '../../config';

const registerController = {
    async register(req, res, next) {
        // CHECKLIST
        // [ ] validate the request
        // [ ] authorise the request
        // [ ] check if user is in the database already
        // [ ] prepare model
        // [ ] store in database
        // [ ] generate jwt token
        // [ ] send response

        // Validation
        const registerSchema = Joi.object({
            name: Joi.string().min(3).max(30).required()
                .pattern(new RegExp(/^[a-zA-Z]+(\s?)+(([a-zA-Z]?))+$/))
                .messages({
                    'string.base': `name should be a type of 'text'`,
                    'string.empty': `name cannot be an empty field`,
                    'string.min': `name should have a minimum length of {#limit}`,
                    'any.required': `name is a required field`,
                    'string.pattern.base': `name accept only alpha`
                }),
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
            confirmPassword: Joi.ref('password')
        });
        const { error } = registerSchema.validate(req.body);
        if (error) {
            return next(error);
        }

        // check if user is in the database already
        try {
            const exist = await User.exists({ email: req.body.email });
            if (exist) {
                return next(CustomErrorHandler.alreadyExist('Email Id already taken'));
            }
        } catch (err) {
            return next(err);
        }
        const { name, email, password } = req.body;

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // prepare the model
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        let access_token;
        let refresh_token;
        try {
            const result = await user.save();

            // Token
            access_token = JwtService.sign({ _id: result._id, role: result.role });
            refresh_token = JwtService.sign({ _id: result._id, role: result.role }, '1y', REFRESH_SECRET);
            // database whitelist
            await RefreshToken.create({ token: refresh_token });
        } catch (err) {
            return next(err);
        }
        res.status(201).json(finalResponce("Register Successfully"));
    }
}


export default registerController;