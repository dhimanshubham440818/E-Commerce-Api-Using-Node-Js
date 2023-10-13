import mongoose from 'mongoose';
import { DB_URL, DB_NAME } from '../config';

// Database connection
export default function dbConnection() {

    mongoose.connect(DB_URL + DB_NAME, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    const db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', () => {
        console.log('DB connected...');
    });

}