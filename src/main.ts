import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
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
        });
        console.log('Conexão ao banco de dados estabelecida.');
        return connection;
    } catch (error: unknown) {
        console.error('Erro ao conectar ao banco:', (error as Error).message);
        throw error;
    }
};

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

// Rota para cadastro de produtos
app.post(
    '/produtos',
    verificarToken, // Middleware para verificar se o usuário está autenticado
    [
        // Validações de entrada usando express-validator
        body('nome').isString().withMessage('Nome do produto deve ser uma string'),
        body('descricao').isString().withMessage('Descrição do produto deve ser uma string'),
        body('preco').isFloat({ gt: 0 }).withMessage('Preço deve ser um número maior que zero'),
        body('imagem')
            .isURL({ require_protocol: true })
            .withMessage('A imagem deve ser uma URL válida'),
        body('estoque').isInt({ gt: -1 }).withMessage('Estoque deve ser um número inteiro maior ou igual a zero'),
    ],
    async (req: Request, res: Response) => {
        // Checa se há erros de validação
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const connection = await createDbConnection(); // Conexão com o banco de dados
            const { nome, descricao, preco, imagem, estoque } = req.body; // Dados do produto recebidos

            // Inserção do novo produto no banco de dados
            await connection.query(
                'INSERT INTO produtos (nome, descricao, preco, estoque, imagem) VALUES (?, ?, ?, ?, ?)',
                [nome, descricao, preco, estoque, imagem]
            );

            await connection.end(); // Fecha a conexão com o banco
            res.status(201).json({ mensagem: 'Produto cadastrado com sucesso!' });
        } catch (error: unknown) {
            const err = error as Error;
            console.error('Erro ao cadastrar produto:', err.message);
            res.status(500).json({ mensagem: 'Erro ao cadastrar produto.' });
        }
    }
);

// Iniciar o servidor
app.listen(8000, () => {
    console.log('Servidor iniciado na porta 8000');
});
