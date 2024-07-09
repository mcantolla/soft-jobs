import express from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
import cors from 'cors';

const { Pool } = pkg
const app = express();
const port = 3000;

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'softjobs',
    password: 'RioSimme4995.',
    port: 5432,
});

app.use(bodyParser.json());


const corsOptions = {
    origin: 'http://localhost:5173',
    optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(bodyParser.json());

const verifyCredentials = (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Faltan credenciales' });
    }
    next();
};

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'Token requerido' });
    }
    jwt.verify(token, 'secretkey', (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: 'Token inválido' });
        }
        req.userEmail = decoded.email;
        next();
    });
};

app.post('/usuarios', verifyCredentials, async (req, res) => {
    const { email, password, rol, lenguage } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    try {
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al registrar usuario' });
    }
});

app.post('/login', verifyCredentials, async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        const token = jwt.sign({ email: user.email }, 'secretkey', { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

app.get('/usuarios', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.userEmail]);
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuario' });
    }
});

app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
