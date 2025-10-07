const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const { config } = require('../config/config');

const AuthService = require('./../services/auth.service');
const UserService = require('./../services/user.service');
const service = new AuthService();
const userService = new UserService();

const router = express.Router();

router.post('/login',
  passport.authenticate('local', { session: false}),
  async (req, res, next) => {
  try {
    const user = req.user;
    res.json(service.signToken(user));
  } catch (error) {
    next(error);
  }
});

router.post('/recovery',
  async (req, res, next) => {
  try {
    const { email } = req.body;
    const rta = await service.resetRecovery(email);
    res.json(rta);
  } catch (error) {
    next(error);
  }
});

router.post('/change-password',
  async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const rta = await service.changePassword(token, newPassword);
    res.json(rta);
  } catch (error) {
    next(error);
  }
});

router.get('/validate-token', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    // Verificar que exista el header y empiece con "Bearer "
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ valid: false, message: 'Token no proporcionado o formato inválido' });
    }

    // Extraer el token del header
    const token = authHeader.split(' ')[1];

    // Verificar la validez del token
    const payload = jwt.verify(token, config.jwtSecret);

    // Buscar el usuario en la base de datos (opcional pero recomendable)
    const user = await userService.findOne(payload.sub);
    if (!user) {
      return res.status(401).json({ valid: false, message: 'Usuario no encontrado' });
    }

    // Si todo va bien, devolver info básica del usuario
    res.json({
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    // Capturar errores específicos
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ valid: false, message: 'Token expirado' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ valid: false, message: 'Token inválido' });
    }

    // Error genérico
    res.status(500).json({ valid: false, message: 'Error al validar el token' });
  }
});

module.exports = router;
