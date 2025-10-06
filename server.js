require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ===================================================================================
// ALTERAÇÃO AQUI: DOIS CLIENTES SUPABASE
// ===================================================================================
// Cliente público para autenticação (login, registro)
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Cliente ADMIN para operações no banco de dados (usado apenas no servidor)
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
// ===================================================================================


// MIDDLEWARE DE AUTENTICAÇÃO (JWT) - Sem alterações
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente' });

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Token inválido' });
    req.user = payload; 
    next();
  });
};

// ROTAS DE AUTENTICAÇÃO (usam o cliente PÚBLICO - sem alterações)
app.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
        return res.status(400).send('Por favor, forneça email, senha e nome.');
    }
    if (!email.endsWith('@viapaineis.com.br')) {
        return res.status(400).send('Cadastro permitido apenas para e-mails do domínio @viapaineis.com.br.');
    }
    const { data, error } = await supabase.auth.signUp({
      email: email,
      password: password,
      options: { data: { full_name: name } }
    });
    if (error) throw error;
    res.status(201).send('Usuário registrado com sucesso! Por favor, verifique seu e-mail para confirmar a conta.');
  } catch (error) {
    console.error('Erro no registro:', error.message);
    res.status(400).send(error.message || 'Erro ao registrar usuário.');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Por favor, forneça email e senha.');
    }
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email,
      password: password,
    });
    if (error) {
      if (error.message === 'Email not confirmed') {
        return res.status(401).send('Login falhou: E-mail ainda não confirmado. Verifique sua caixa de entrada.');
      }
      throw error;
    }
    const userPayload = { 
        id: data.user.id, 
        name: data.user.user_metadata.full_name,
        email: data.user.email
    };
    const appToken = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.status(200).json({ token: appToken, user: userPayload });
  } catch (error) {
    console.error('Erro de login:', error.message);
    res.status(400).send(error.message || 'Email ou senha inválidos.');
  }
});


// ===================================================================================
// ALTERAÇÃO AQUI: ROTAS DE PROPOSTAS USAM O CLIENTE ADMIN
// ===================================================================================
app.get('/propostas', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // Usa o cliente ADMIN para ler os dados
    const { data, error } = await supabaseAdmin
      .from('proposals')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Erro ao buscar propostas:', error);
    res.status(500).send('Erro no servidor ao buscar propostas.');
  }
});

app.post('/propostas', authenticateToken, async (req, res) => {
  try {
    const { title, data: proposalData } = req.body;
    const userId = req.user.id;

    // Usa o cliente ADMIN para inserir os dados
    const { data: inserted, error } = await supabaseAdmin
      .from('proposals')
      .insert([{ user_id: userId, title: title, data: proposalData }])
      .select();

    if (error) throw error;
    res.status(201).send('Proposta salva com sucesso!');
  } catch (error) {
    console.error('Erro ao salvar proposta:', error);
    res.status(500).send('Erro no servidor ao salvar proposta.');
  }
});


app.listen(PORT, () => {
  console.log(`Servidor backend a correr na porta ${PORT}`);
});