import { DEBUG_MODE } from '../config';
import { ValidationError } from 'joi';
import CustomErrorHandler from '../services/CustomErrorHandler';

const errorHandler = (err, req, res, next) => {
    let statusCode = 500;
    let data = {
        status: false,
        error:true,
        result:null,
        message: 'Internal server error',
        ...(DEBUG_MODE === 'true' && { originalError: err })
    }

    if (err instanceof ValidationError) {
        statusCode = 422;
        data = {
            status: false,
            error:true,
            result:null,
            message: err.message
        }
    }

    if (err instanceof CustomErrorHandler) {
        statusCode = err.status;
        data = {
            status: false,
            error:true,
            result:null,
            message: err.message
        }
    }

    return res.status(statusCode).json(data);
}

export default errorHandler;