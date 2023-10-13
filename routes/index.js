import { registerController, loginController, userController, refreshController, productController } from '../controllers';
import admin from '../middlewares/admin';
import auth from '../middlewares/auth';
import express from 'express';
const router = express.Router();

router.post('/register', registerController.register);
router.post('/login', loginController.login);
router.get('/me', auth, userController.me);
router.post('/refresh', refreshController.refresh);
router.post('/logout', auth, loginController.logout);

router.post('/products/cart-items', productController.getProducts);

router.post('/products', [auth, admin], productController.add);
router.get('/products', productController.products);
router.put('/products/:id', [auth, admin], productController.update);
router.delete('/products/:id', [auth, admin], productController.destroy);
router.get('/products/:id', productController.single);

export default router;