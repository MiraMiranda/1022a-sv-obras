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
const upload = multer({ storage });

const app = express();
app.use(express.json());
app.use(cors());

// Função para criar a conexão com o banco de dados
const createDbConnection = async () => {
    return await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'banco1022a',
        port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
    });
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
        req.usuarioId = decoded.id;  // Agora funciona sem erro
        next();
    } catch (e: unknown) {
        // Cast para 'Error' para acessar e.message e e.stack
        const error = e as Error;
        console.error('Token inválido:', error.message);
        res.status(400).send('Token inválido.');
    }
};

// Rota para cadastro de novo usuário com upload de imagem
app.post('/usuarios/cadastro', 
    upload.single('imagem'),
    [
        body('nome').isString().withMessage('Nome deve ser uma string'),
        body('cpf').isString().withMessage('CPF deve ser uma string'),
        body('codigoEmpresarial').isString().withMessage('Código Empresarial deve ser uma string'),
        body('senha').isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres')
    ], 
    async (req: Request, res: Response) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const connection = await createDbConnection();
            const { nome, cpf, codigoEmpresarial, senha } = req.body;

            // Verificar se o código empresarial já existe
            const [existeCodigo] = await connection.query(
                'SELECT * FROM usuarios WHERE codigoEmpresarial = ?',
                [codigoEmpresarial]
            );

            if (Array.isArray(existeCodigo) && existeCodigo.length > 0) {
                return res.status(400).send('Código empresarial já registrado.');
            }

            // Criptografar a senha
            const senhaHash = bcrypt.hashSync(senha, 10);

            // Obter o arquivo de imagem como binário
            const imagem = req.file ? req.file.buffer : null;

            // Inserir novo usuário com a imagem como binário
            await connection.query(
                'INSERT INTO usuarios (nome, cpf, codigoEmpresarial, senha, imagem) VALUES (?, ?, ?, ?, ?)',
                [nome, cpf, codigoEmpresarial, senhaHash, imagem]
            );

            await connection.end();
            res.send({ mensagem: 'Usuário cadastrado com sucesso!' });
        } catch (e: unknown) {
            // Cast para 'Error' para acessar e.message e e.stack
            const error = e as Error;
            console.error('Erro ao cadastrar usuário:', error.message);
            console.error('Stack Trace:', error.stack);
            res.status(500).send('Erro ao cadastrar usuário.');
        }
    }
);

// Rota de login para gerar o token JWT
app.post('/usuarios/login', async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        const { codigoEmpresarial, senha } = req.body;

        // Buscar usuário pelo código empresarial
        const [usuarios] = await connection.query(
            'SELECT * FROM usuarios WHERE codigoEmpresarial = ?',
            [codigoEmpresarial]
        );

        if ((usuarios as any[]).length === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado' });
        }

        const usuario = (usuarios as any[])[0];

        // Verificar a senha
        const senhaValida = bcrypt.compareSync(senha, usuario.senha);
        if (!senhaValida) {
            return res.status(400).json({ mensagem: 'Senha incorreta' });
        }

        // Gerar um token JWT
        const token = jwt.sign({ id: usuario.codigoEmpresarial }, 'segredo', {
            expiresIn: '1h',
        });

        await connection.end();
        res.send({ token });
    } catch (e: unknown) {
        // Cast para 'Error' para acessar e.message e e.stack
        const error = e as Error;
        console.error('Erro ao fazer login:', error.message);
        console.error('Stack Trace:', error.stack);
        res.status(500).send('Erro ao fazer login');
    }
});

// Rota protegida (exemplo de como usar o middleware de verificação de token)
app.get('/usuarios/me', verificarToken, async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        const [usuarios] = await connection.query(
            'SELECT * FROM usuarios WHERE codigoEmpresarial = ?',
            [req.usuarioId]
        );

        if ((usuarios as any[]).length === 0) {
            return res.status(400).send('Usuário não encontrado');
        }

        const usuario = (usuarios as any[])[0];
        res.send(usuario);
    } catch (e: unknown) {
        // Cast para 'Error' para acessar e.message e e.stack
        const error = e as Error;
        console.error('Erro ao obter dados do usuário:', error.message);
        console.error('Stack Trace:', error.stack);
        res.status(500).send('Erro ao obter dados do usuário.');
    }
});

// Rota para excluir um usuário
app.delete('/usuarios/deletar', verificarToken, async (req: Request, res: Response) => {
    try {
        const connection = await createDbConnection();
        
        // Excluir usuário
        const [result] = await connection.query(
            'DELETE FROM usuarios WHERE codigoEmpresarial = ?',
            [req.usuarioId]
        );
        
        // Verificar se o usuário foi encontrado e excluído
        if ((result as mysql.ResultSetHeader).affectedRows === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        
        res.send({ mensagem: 'Usuário excluído com sucesso!' });
    } catch (e: unknown) {
        // Cast para 'Error' para acessar e.message e e.stack
        const error = e as Error;
        console.error('Erro ao excluir usuário:', error.message);
        console.error('Stack Trace:', error.stack);
        res.status(500).send('Erro ao excluir usuário.');
    }
});

// Iniciar o servidor
app.listen(8000, () => {
    console.log('Servidor iniciado na porta 8000');
});
