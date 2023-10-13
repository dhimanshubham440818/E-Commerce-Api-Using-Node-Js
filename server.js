import errorHandler from './middlewares/errorHandler';
import dbConnection from './config/dbConnection';
import express from 'express';
import routes from './routes';
import path from 'path';
import cors from 'cors';
import { APP_PORT } from './config';
const app = express();
dbConnection();

global.appRoot = path.resolve(__dirname);

app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use('/api', routes);
app.use('/uploads', express.static('uploads'));

app.use(errorHandler);
const PORT = process.env.PORT || APP_PORT;
app.listen(PORT, () => console.log(`Listening on port ${PORT}.`));