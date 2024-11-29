import express from 'express'
import mysql from 'mysql2/promise'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// Tipo para os dados dos usuários
type UsuarioType = {
    id: number;
    nome: string;
    cpf: string;
    codigoEmpresarial: string;
    senha: string;
}

const app = express()
app.use(express.json())
app.use(cors())

// Função para criar a conexão com o banco de dados
const createDbConnection = async () => {
    return await mysql.createConnection({
        host: process.env.dbhost ? process.env.dbhost : "localhost",
        user: process.env.dbuser ? process.env.dbuser : "root",
        password: process.env.dbpassword ? process.env.dbpassword : "",
        database: process.env.dbname ? process.env.dbname : "banco1022a",
        port: process.env.dbport ? parseInt(process.env.dbport) : 3306
    })
}

// Rota para obter os usuários
app.get("/usuarios", async (req, res) => {
    try {
        const connection = await createDbConnection()

        // Modificamos a forma de desestruturar o retorno
        const [usuarios] = await connection.query("SELECT * from usuarios")

        // Verificar se existem usuários
        if ((usuarios as UsuarioType[]).length === 0) {
            return res.status(404).send("Nenhum usuário encontrado.")
        }

        await connection.end()
        res.send(usuarios)
    } catch (e) {
        console.log(e)
        res.status(500).send("Server ERROR")
    }
})

// Rota para cadastro de novo usuário
app.post("/usuarios/cadastro", async (req, res) => {
    try {
        const connection = await createDbConnection()
        const { nome, cpf, codigoEmpresarial, senha } = req.body

        // Verificar se o código empresarial já existe
        const [existeCodigo] = await connection.query("SELECT * FROM usuarios WHERE codigoEmpresarial = ?", [codigoEmpresarial])

        if ((existeCodigo as UsuarioType[]).length > 0) {
            return res.status(400).send("Código empresarial já registrado.")
        }

        // Criptografar a senha
        const senhaHash = bcrypt.hashSync(senha, 10)

        // Inserir novo usuário
        await connection.query("INSERT INTO usuarios (nome, cpf, codigoEmpresarial, senha) VALUES (?, ?, ?, ?)", [nome, cpf, codigoEmpresarial, senhaHash])

        await connection.end()
        res.send({ mensagem: "Usuário cadastrado com sucesso!" })
    } catch (e) {
        console.log(e)
        res.status(500).send("Erro ao cadastrar usuário.")
    }
})

// Rota para login de usuário
app.post("/usuarios/login", async (req, res) => {
    try {
        const connection = await createDbConnection()
        const { codigoEmpresarial, senha } = req.body

        // Buscar usuário pelo código empresarial
        const [usuarios] = await connection.query("SELECT * FROM usuarios WHERE codigoEmpresarial = ?", [codigoEmpresarial])

        // Verificar se o usuário foi encontrado
        if ((usuarios as UsuarioType[]).length === 0) {
            return res.status(400).send({ mensagem: "Usuário não encontrado" })
        }

        const usuario = (usuarios as UsuarioType[])[0]

        // Verificar a senha
        const senhaValida = bcrypt.compareSync(senha, usuario.senha)
        if (!senhaValida) {
            return res.status(400).send({ mensagem: "Senha incorreta" })
        }

        // Gerar um token JWT
        const token = jwt.sign({ id: usuario.codigoEmpresarial }, 'segredo', { expiresIn: '1h' })

        await connection.end()
        res.send({ token })
    } catch (e) {
        console.log(e)
        res.status(500).send("Erro ao fazer login")
    }
})

// Rota para obter os produtos
app.get("/produtos", async (req, res) => {
    try {
        const connection = await createDbConnection()
        const [result] = await connection.query("SELECT * from produtos")
        await connection.end()
        res.send(result)
    } catch (e) {
        console.log(e)
        res.status(500).send("Server ERROR")
    }
})

// Rota para adicionar um produto
app.post("/produtos", async (req, res) => {
    try {
        const connection = await createDbConnection()
        const { id, nome, descricao, preco, imagem } = req.body
        const [result] = await connection.query("INSERT INTO produtos VALUES (?,?,?,?,?)", [id, nome, descricao, preco, imagem])
        await connection.end()
        res.send(result)
    } catch (e) {
        console.log(e)
        res.status(500).send("Erro ao adicionar produto.")
    }
})

// Iniciar o servidor
app.listen(8000, () => {
    console.log("Iniciei o servidor")
})
