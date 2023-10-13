import dotenv from 'dotenv';
dotenv.config();

export const {
    APP_PORT,
    DEBUG_MODE,
    DB_URL,
    DB_NAME,
    JWT_SECRET,
    APP_URL,
    REFRESH_SECRET,
} = process.env;