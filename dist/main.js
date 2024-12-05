"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const promise_1 = __importDefault(require("mysql2/promise"));
const cors_1 = __importDefault(require("cors"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
const multer_1 = __importDefault(require("multer"));
const fs_1 = __importDefault(require("fs"));
const express_validator_1 = require("express-validator");
dotenv_1.default.config();
// Configuração do multer para upload de arquivos
const storage = multer_1.default.memoryStorage(); // Usando storage na memória para salvar a imagem como binário
const upload = (0, multer_1.default)({ storage });
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((0, cors_1.default)());
// Função para criar a conexão com o banco de dados
const createDbConnection = async () => {
    try {
        const connection = await promise_1.default.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'banco1022a',
            port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
            ssl: {
                ca: fs_1.default.readFileSync('./ca.pem'), // Certificado CA baixado do painel do Aiven
            },
        });
        console.log('Conexão ao banco de dados estabelecida.');
        return connection;
    }
    catch (error) {
        console.error('Erro ao conectar ao banco:', error.message);
        throw error; // Relança o erro para capturá-lo nos endpoints
    }
};
// Middleware para verificar o token JWT
const verificarToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).send('Acesso negado. Token não fornecido.');
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, 'segredo');
        req.usuarioId = decoded.id;
        next();
    }
    catch (e) {
        const error = e;
        console.error('Token inválido:', error.message);
        res.status(400).send('Token inválido.');
    }
};
// Rota para testar a conexão com o banco de dados
app.get('/test-db', async (req, res) => {
    try {
        const connection = await createDbConnection();
        await connection.query('SELECT 1 + 1 AS result'); // Consulta simples
        await connection.end();
        res.status(200).send('Conexão ao banco de dados bem-sucedida!');
    }
    catch (e) {
        const error = e;
        console.error('Erro ao conectar ao banco:', error.message);
        res.status(500).send('Erro ao conectar ao banco de dados.');
    }
});
// Rota para cadastro de novo usuário com upload de imagem
app.post('/usuarios/cadastro', upload.single('imagem'), [
    (0, express_validator_1.body)('nome').isString().withMessage('Nome deve ser uma string'),
    (0, express_validator_1.body)('cpf').isString().withMessage('CPF deve ser uma string'),
    (0, express_validator_1.body)('codigoEmpresarial').isString().withMessage('Código Empresarial deve ser uma string'),
    (0, express_validator_1.body)('senha').isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres'),
], async (req, res) => {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const connection = await createDbConnection();
        const { nome, cpf, codigoEmpresarial, senha } = req.body;
        const [existeCodigo] = await connection.query('SELECT * FROM usuarios WHERE codigoEmpresarial = ?', [codigoEmpresarial]);
        if (Array.isArray(existeCodigo) && existeCodigo.length > 0) {
            return res.status(400).send('Código empresarial já registrado.');
        }
        const senhaHash = bcryptjs_1.default.hashSync(senha, 10);
        const imagem = req.file ? req.file.buffer : null;
        await connection.query('INSERT INTO usuarios (nome, cpf, codigoEmpresarial, senha, imagem) VALUES (?, ?, ?, ?, ?)', [nome, cpf, codigoEmpresarial, senhaHash, imagem]);
        await connection.end();
        res.send({ mensagem: 'Usuário cadastrado com sucesso!' });
    }
    catch (e) {
        const error = e;
        console.error('Erro ao cadastrar usuário:', error.message);
        res.status(500).send('Erro ao cadastrar usuário.');
    }
});
// Rota de login para gerar o token JWT
app.post('/usuarios/login', async (req, res) => {
    try {
        const connection = await createDbConnection();
        const { codigoEmpresarial, senha } = req.body;
        const [usuarios] = await connection.query('SELECT * FROM usuarios WHERE codigoEmpresarial = ?', [codigoEmpresarial]);
        if (usuarios.length === 0) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado' });
        }
        const usuario = usuarios[0];
        const senhaValida = bcryptjs_1.default.compareSync(senha, usuario.senha);
        if (!senhaValida) {
            return res.status(400).json({ mensagem: 'Senha incorreta' });
        }
        const token = jsonwebtoken_1.default.sign({ id: usuario.codigoEmpresarial }, 'segredo', {
            expiresIn: '1h',
        });
        await connection.end();
        res.send({ token });
    }
    catch (e) {
        const error = e;
        console.error('Erro ao fazer login:', error.message);
        res.status(500).send('Erro ao fazer login');
    }
});
// Iniciar o servidor
app.listen(8000, () => {
    console.log('Servidor iniciado na porta 8000');
});
