import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import multer from 'multer';
import fs from 'fs';
import { body, validationResult } from 'express-validator';

dotenv.config();

// Estendendo o tipo Request do Express para adicionar usuarioId
declare global {
    namespace Express {
        interface Request {
            usuarioId?: string; // Adiciona a propriedade usuarioId ao tipo Request
        }
    }
}

// Configuração do multer para upload de arquivos
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            const error = new Error('Apenas imagens são permitidas!') as any;
            error.code = 'LIMIT_UNEXPECTED_FILE';
            return cb(error, false);
        }
        cb(null, true);
    },
});

const app = express();
app.use(express.json());

// Configuração de CORS
const allowedOrigins = ['http://localhost:5173'];
app.use(
    cors({
        origin: allowedOrigins,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: true,
    })
);

// Middleware para tratar erros de upload com multer
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).send({ error: 'Apenas imagens são permitidas!' });
    }
    next(err);
});

// Middleware para verificar o token JWT
const verificarToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Pega o token do header Authorization

    if (!token) {
        return res.status(401).json({ mensagem: 'Token não fornecido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'default_secret', (err: any, decoded: any) => {
        if (err) {
            return res.status(403).json({ mensagem: 'Token inválido' });
        }

        req.usuarioId = decoded.id; // Atribui o id do usuário ao request para futuras consultas
        next();
    });
};

// Função para criar a conexão com o banco de dados
const createDbConnection = async () => {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'banco1022a',
            port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
            ssl: process.env.DB_SSL
                ? {
                      ca: fs.readFileSync('./ca.pem'),
                  }
                : undefined,
        });
        console.log('Conexão ao banco de dados estabelecida.');
        return connection;
    } catch (error: unknown) {
        console.error('Erro ao conectar ao banco:', (error as Error).message);
        throw error;
    }
};

// Rota para testar a conexão com o banco de dados
app.get('/test-db', async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        await connection.query('SELECT 1 + 1 AS result');
        await connection.end();
        res.status(200).send('Conexão ao banco de dados bem-sucedida!');
    } catch (e: unknown) {
        const error = e as Error;
        console.error('Erro ao conectar ao banco:', error.message);
        res.status(500).send('Erro ao conectar ao banco de dados.');
    }
});

// Rota para listar todos os produtos
app.get('/produtos', async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        const [produtos] = await connection.query('SELECT * FROM produtos');
        await connection.end();

        if (Array.isArray(produtos) && produtos.length > 0) {
            res.status(200).json(produtos);
        } else {
            res.status(404).json({ mensagem: 'Nenhum produto encontrado.' });
        }
    } catch (e: unknown) {
        const error = e as Error;
        console.error('Erro ao buscar produtos:', error.message);
        res.status(500).json({ mensagem: 'Erro ao buscar produtos.' });
    }
});

// Rota para cadastro de novo produto
app.post(
    '/produtos',
    [
        body('id').notEmpty().withMessage('O campo ID é obrigatório'),
        body('nome').isString().withMessage('O nome deve ser uma string'),
        body('descricao').isString().withMessage('A descrição deve ser uma string'),
        body('preco').isNumeric().withMessage('O preço deve ser um número'),
        body('imagem').isString().withMessage('O campo imagem deve ser uma string'),
        body('estoque').isNumeric().withMessage('O estoque deve ser um número'),
    ],
    async (req: Request, res: Response) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { id, nome, descricao, preco, imagem, estoque } = req.body;

        try {
            const connection = await createDbConnection();

            // Verifica se o produto já existe pelo ID
            const [produtoExistente] = await connection.query(
                'SELECT * FROM produtos WHERE id = ?',
                [id]
            );

            if (Array.isArray(produtoExistente) && produtoExistente.length > 0) {
                await connection.end();
                return res.status(409).json({ mensagem: 'Produto com este ID já existe.' });
            }

            await connection.query(
                'INSERT INTO produtos (id, nome, descricao, preco, imagem, estoque) VALUES (?, ?, ?, ?, ?, ?)',
                [id, nome, descricao, preco, imagem, estoque]
            );
            await connection.end();

            res.status(201).json({ mensagem: 'Produto cadastrado com sucesso!' });
        } catch (e: unknown) {
            const error = e as Error;
            console.error('Erro ao cadastrar produto:', error.message);
            res.status(500).send('Erro ao cadastrar produto.');
        }
    }
);

// Rota para cadastro de novo usuário com upload de imagem
app.post(
    '/cadastro',
    upload.single('imagem'),
    [
        body('nome').isString().withMessage('Nome deve ser uma string'),
        body('cpf').isString().withMessage('CPF deve ser uma string'),
        body('codigoEmpresarial').isString().withMessage('Código Empresarial deve ser uma string'),
        body('senha').isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres'),
    ],
    async (req: Request, res: Response) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const connection = await createDbConnection();
            const { nome, cpf, codigoEmpresarial, senha } = req.body;

            const [existeCodigo] = await connection.query(
                'SELECT * FROM usuarios WHERE codigoEmpresarial = ?',
                [codigoEmpresarial]
            );

            if (Array.isArray(existeCodigo) && existeCodigo.length > 0) {
                return res.status(400).send('Código empresarial já registrado.');
            }

            const senhaHash = bcrypt.hashSync(senha, 10);
            const imagem = req.file ? req.file.buffer : null;

            await connection.query(
                'INSERT INTO usuarios (nome, cpf, codigoEmpresarial, senha, imagem) VALUES (?, ?, ?, ?, ?)',
                [nome, cpf, codigoEmpresarial, senhaHash, imagem]
            );

            await connection.end();
            res.send({ mensagem: 'Usuário cadastrado com sucesso!' });
        } catch (e: unknown) {
            const error = e as Error;
            console.error('Erro ao cadastrar usuário:', error.message);
            res.status(500).send('Erro ao cadastrar usuário.');
        }
    }
);

// Rota de login para gerar o token JWT
app.post(
    '/usuarios/login',
    [
        body('codigoEmpresarial').isString().withMessage('Código Empresarial deve ser uma string'),
        body('senha').isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres'),
    ],
    async (req: Request, res: Response) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const connection = await createDbConnection();
            const { codigoEmpresarial, senha } = req.body;

            const [usuarios] = await connection.query(
                'SELECT * FROM usuarios WHERE codigoEmpresarial = ?',
                [codigoEmpresarial]
            );

            if ((usuarios as any[]).length === 0) {
                return res.status(404).json({ mensagem: 'Usuário não encontrado' });
            }

            const usuario = (usuarios as any[])[0];

            const senhaValida = bcrypt.compareSync(senha, usuario.senha);
            if (!senhaValida) {
                return res.status(401).json({ mensagem: 'Credenciais inválidas' });
            }

            const token = jwt.sign(
                { id: usuario.id, nome: usuario.nome },
                process.env.JWT_SECRET || 'default_secret',
                { expiresIn: '8h' }
            );

            res.status(200).json({ token });
        } catch (e: unknown) {
            const error = e as Error;
            console.error('Erro ao fazer login:', error.message);
            res.status(500).send('Erro ao fazer login.');
        }
    }
);

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
