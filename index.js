const express = require('express');
const cors = require('cors');
const routerApi = require('./routes');

const { logErrors, errorHandler, boomErrorHandler, ormErrorHandler } = require('./middlewares/error.handler');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// 🔹 Lista de orígenes permitidos
const whitelist = ['http://localhost:3001', 'https://enrique1994mex.github.io'];

// 🔹 Opciones de CORS
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || whitelist.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      callback(new Error('Acceso no permitido por CORS'));
    }
  },
  credentials: true, // Permite el uso de cookies o autenticación
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Métodos permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Headers permitidos
};
app.use(cors(corsOptions));

require('./utils/auth');

routerApi(app);

app.use(logErrors);
app.use(ormErrorHandler);
app.use(boomErrorHandler);
app.use(errorHandler);


app.listen(port, () => {
  console.log('Mi port' +  port);
});
