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
const storage = multer.memoryStorage(); // Usando storage na memória para salvar a imagem como binário

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        // Validação de arquivo: permitir apenas imagens
        if (!file.mimetype.startsWith('image/')) {
            // Criar um erro de forma genérica
            const error = new Error('Apenas imagens são permitidas!');
            return cb(error, false); // Passa o erro corretamente
        }
        cb(null, true); // Se o arquivo for válido, permite o upload
    },
});

const app = express();
app.use(express.json());
app.use(cors());

// Função para criar a conexão com o banco de dados
const createDbConnection = async () => {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'banco1022a',
            port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
            ssl: {
                ca: fs.readFileSync('./ca.pem'), // Certificado CA baixado do painel do Aiven
            },
        });
        console.log('Conexão ao banco de dados estabelecida.');
        return connection;
    } catch (error: unknown) {
        console.error('Erro ao conectar ao banco:', (error as Error).message);
        throw error; // Relança o erro para capturá-lo nos endpoints
    }
};

// Definir o tipo do payload para o token JWT
interface JwtPayload {
    id: string;
}

// Middleware para verificar o token JWT
const verificarToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).send('Acesso negado. Token não fornecido.');
    }
    try {
        const decoded = jwt.verify(token, 'segredo') as JwtPayload;
        req.usuarioId = decoded.id;
        next();
    } catch (e: unknown) {
        const error = e as Error;
        console.error('Token inválido:', error.message);
        res.status(400).send('Token inválido.');
    }
};

// Rota para testar a conexão com o banco de dados
app.get('/test-db', async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        await connection.query('SELECT 1 + 1 AS result'); // Consulta simples
        await connection.end();
        res.status(200).send('Conexão ao banco de dados bem-sucedida!');
    } catch (e: unknown) {
        const error = e as Error;
        console.error('Erro ao conectar ao banco:', error.message);
        res.status(500).send('Erro ao conectar ao banco de dados.');
    }
});

// Rota para cadastro de novo usuário com upload de imagem
app.post(
    '/usuarios/cadastro',
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
app.post('/usuarios/login', async (req: Request, res: Response) => {
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
            return res.status(400).json({ mensagem: 'Senha incorreta' });
        }

        const token = jwt.sign({ id: usuario.codigoEmpresarial }, 'segredo', {
            expiresIn: '1h',
        });

        await connection.end();
        res.send({ token });
    } catch (e: unknown) {
        const error = e as Error;
        console.error('Erro ao fazer login:', error.message);
        res.status(500).send('Erro ao fazer login');
    }
});

// Iniciar o servidor
app.listen(8000, () => {
    console.log('Servidor iniciado na porta 8000');
});
