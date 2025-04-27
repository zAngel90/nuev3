const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// Bold API Configuration
const BOLD_API_URL = 'https://integrations.api.bold.co';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const BOLD_API_KEY = 'zwSnBgN6F1NaDAj8vPQCuiUSFjy214ly-guw0smJdzo';

// Middleware
app.use(cors({
  origin: true, // Permite cualquier origen
  credentials: true, // Permite credenciales
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-bold-signature', 'Origin', 'Accept'],
  exposedHeaders: ['Content-Range', 'X-Content-Range']
}));

// Middleware para preflight requests
app.options('*', cors());

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Configuración de multer para subida de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

// Rutas de la API
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const TRANSACTIONS_FILE = path.join(__dirname, 'data', 'transactions.json');
const PRODUCTS_FILE = path.join(__dirname, 'data', 'products.json');
const CATEGORIES_FILE = path.join(__dirname, 'data', 'categories.json');

// Función auxiliar para leer archivos JSON
async function readJSONFile(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading ${filePath}:`, error);
    return null;
  }
}

// Función auxiliar para escribir archivos JSON
async function writeJSONFile(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Error writing ${filePath}:`, error);
    return false;
  }
}

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, 'tu_secreto_jwt');
    req.user = decoded;
      next();
  } catch (error) {
    console.error('Error de autenticación:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado' });
    }
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Endpoint de registro
app.post('/api/users/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validaciones básicas
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    // Leer usuarios existentes
    const usersData = await readJSONFile(USERS_FILE);
    if (!usersData) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    // Verificar si el usuario ya existe
    const userExists = usersData.users.some(
      user => user.username === username || user.email === email
    );

    if (userExists) {
      return res.status(400).json({ error: 'Usuario o email ya registrado' });
    }

    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const newUser = {
      id: String(usersData.users.length + 1),
      username,
      email,
      password: hashedPassword,
      balance: 0,
      transactions: [],
      role: 'user',
      createdAt: new Date().toISOString()
    };

    // Guardar usuario
    usersData.users.push(newUser);
    const saved = await writeJSONFile(USERS_FILE, usersData);

    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar el usuario' });
    }

    // Generar token
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, role: newUser.role },
      'tu_secreto_jwt',
      { expiresIn: '24h' }
    );

    // Responder sin incluir la contraseña
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({
      user: userWithoutPassword,
      token
    });

  } catch (error) {
    console.error('Error en el registro:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint de login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validaciones básicas
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    // Leer usuarios
    const usersData = await readJSONFile(USERS_FILE);
    if (!usersData) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    // Buscar usuario
    const user = usersData.users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Generar token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      'tu_secreto_jwt',
      { expiresIn: '24h' }
    );

    // Responder sin incluir la contraseña
    const { password: _, ...userWithoutPassword } = user;
    res.json({ 
      user: userWithoutPassword,
      token
    });

  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint para obtener el balance
app.get('/api/users/balance', authenticateToken, async (req, res) => {
  try {
    const usersData = await readJSONFile(USERS_FILE);
    if (!usersData) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    const user = usersData.users.find(u => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ balance: user.balance });
  } catch (error) {
    console.error('Error al obtener balance:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint para recargar saldo
app.post('/api/users/recharge', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount < 1000) {
      return res.status(400).json({ error: 'Monto inválido' });
    }

    const usersData = await readJSONFile(USERS_FILE);
    const transactionsData = await readJSONFile(TRANSACTIONS_FILE);

    if (!usersData || !transactionsData) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    // Actualizar balance del usuario
    const userIndex = usersData.users.findIndex(u => u.id === req.user.id);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    usersData.users[userIndex].balance += Number(amount);

    // Crear transacción
    const newTransaction = {
      id: String(transactionsData.transactions.length + 1),
      userId: req.user.id,
      type: 'RECHARGE',
      amount: Number(amount),
      status: 'COMPLETED',
      description: 'Recarga de saldo',
      createdAt: new Date().toISOString()
    };

    transactionsData.transactions.push(newTransaction);

    // Guardar cambios
    const savedUser = await writeJSONFile(USERS_FILE, usersData);
    const savedTransaction = await writeJSONFile(TRANSACTIONS_FILE, transactionsData);

    if (!savedUser || !savedTransaction) {
      return res.status(500).json({ error: 'Error al guardar los cambios' });
    }

    res.json({
      balance: usersData.users[userIndex].balance,
      transaction: newTransaction
    });

  } catch (error) {
    console.error('Error en la recarga:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Endpoint para obtener transacciones
app.get('/api/users/transactions', authenticateToken, async (req, res) => {
  try {
    const transactionsData = await readJSONFile(TRANSACTIONS_FILE);
    if (!transactionsData) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    // Filtrar transacciones por userId
    const userTransactions = transactionsData.transactions
      .filter(t => t.userId === req.user.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); // Ordenar por fecha, más recientes primero

    res.json({ transactions: userTransactions });
  } catch (error) {
    console.error('Error al obtener transacciones:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Auth middleware
const isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Product routes
app.get('/api/products', async (req, res) => {
  try {
    const data = await readJSONFile(PRODUCTS_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }
    res.json(data.products);
  } catch (error) {
    res.status(500).json({ error: 'Error al cargar los productos' });
  }
});

app.post('/api/products', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, category, tag } = req.body;
    const data = await readJSONFile(PRODUCTS_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'La imagen es requerida' });
    }

    const newProduct = {
      id: String(data.products.length + 1),
      name,
      description,
      price: parseFloat(price),
      image: `http://localhost:5000/uploads/products/${req.file.filename}`,
      category,
      tag,
      createdAt: new Date().toISOString(),
      createdBy: req.user.username,
      discount: null
    };

    data.products.push(newProduct);
    const saved = await writeJSONFile(PRODUCTS_FILE, data);
    
    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar el producto' });
    }

    res.status(201).json(newProduct);
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ error: 'Error al crear el producto' });
  }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await readJSONFile(PRODUCTS_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }
    
    const product = data.products.find(p => p.id === id);
    if (!product) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    if (product.image) {
      const imagePath = product.image.replace('http://localhost:5000', '.');
      try {
        await fs.unlink(imagePath);
      } catch (err) {
        console.error('Error al eliminar imagen:', err);
      }
    }

    data.products = data.products.filter(p => p.id !== id);
    const saved = await writeJSONFile(PRODUCTS_FILE, data);

    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar los cambios' });
    }

    res.json({ message: 'Producto eliminado correctamente' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Error al eliminar el producto' });
  }
});

// Categories routes
app.get('/api/categories', async (req, res) => {
  try {
    const data = await readJSONFile(CATEGORIES_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }
    res.json(data.categories);
  } catch (error) {
    res.status(500).json({ error: 'Error al cargar las categorías' });
  }
});

app.post('/api/categories', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const data = await readJSONFile(CATEGORIES_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }
    
    const slug = name.toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-');

    const newCategory = {
      id: String(data.categories.length + 1),
      name,
      slug,
      description
    };

    data.categories.push(newCategory);
    const saved = await writeJSONFile(CATEGORIES_FILE, data);

    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar la categoría' });
    }

    res.status(201).json(newCategory);
  } catch (error) {
    res.status(500).json({ error: 'Error al crear la categoría' });
  }
});

app.put('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;
    const data = await readJSONFile(CATEGORIES_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    const categoryIndex = data.categories.findIndex(c => c.id === id);
    if (categoryIndex === -1) {
      return res.status(404).json({ error: 'Categoría no encontrada' });
    }

    const slug = name.toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-');

    const updatedCategory = {
      ...data.categories[categoryIndex],
      name,
      slug,
      description
    };

    data.categories[categoryIndex] = updatedCategory;
    const saved = await writeJSONFile(CATEGORIES_FILE, data);

    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar los cambios' });
    }

    res.json(updatedCategory);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar la categoría' });
  }
});

app.delete('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const data = await readJSONFile(CATEGORIES_FILE);
    if (!data) {
      return res.status(500).json({ error: 'Error al leer la base de datos' });
    }

    const categoryIndex = data.categories.findIndex(c => c.id === id);
    if (categoryIndex === -1) {
      return res.status(404).json({ error: 'Categoría no encontrada' });
    }

    data.categories = data.categories.filter(c => c.id !== id);
    const saved = await writeJSONFile(CATEGORIES_FILE, data);

    if (!saved) {
      return res.status(500).json({ error: 'Error al guardar los cambios' });
    }

    res.json({ message: 'Categoría eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar la categoría' });
  }
});

// Endpoint para crear link de pago Bold
app.post('/api/payments/create', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount < 1000) {
      return res.status(400).json({ error: 'Monto inválido. Mínimo $1,000' });
    }
    
    const paymentData = {
      amount_type: "CLOSE",
      amount: {
        currency: "COP",
        total_amount: Number(amount),
        tip_amount: 0
      },
      description: "Recarga de saldo",
      metadata: { 
        reference: 'LNK_' + Math.random().toString(36).substr(2, 9).toUpperCase(),
        userId: req.user.id,
        type: "RECHARGE"
      },
      payment_methods: ["CREDIT_CARD", "PSE", "NEQUI"]
    };

    console.log('Enviando solicitud a Bold:', paymentData);

    const response = await fetch(`${BOLD_API_URL}/online/link/v1`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `x-api-key ${BOLD_API_KEY}`
      },
      body: JSON.stringify(paymentData)
    });

    if (!response.ok) {
      console.error('Error creando pago en Bold:', response.status);
      const errorText = await response.text();
      console.error('Detalles del error:', errorText);
      return res.status(response.status).json({ error: 'Error al crear el pago' });
    }

    const boldResponse = await response.json();
    console.log('Respuesta de Bold:', boldResponse);
    
    res.json({
      success: true,
      payload: {
        url: boldResponse.payload.url,
        payment_link: boldResponse.payload.payment_link
      }
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para verificar métodos de pago disponibles
app.get('/api/payments/methods', authenticateToken, async (req, res) => {
  try {
    const response = await fetch(`${BOLD_API_URL}/online/link/v1/payment_methods`, {
      method: 'GET',
      headers: {
        'Authorization': `x-api-key ${BOLD_API_KEY}`
      }
    });

    if (!response.ok) {
      console.error('Error consultando métodos de pago:', response.status);
      const errorText = await response.text();
      console.error('Detalles del error:', errorText);
      return res.status(response.status).json({ error: 'Error al consultar métodos de pago' });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Función para verificar la firma del webhook de Bold
const verifyBoldSignature = (signature, body) => {
  try {
    const encoded = Buffer.from(JSON.stringify(body)).toString('base64');
    // Usar la llave secreta de pruebas proporcionada
    const secretKey = 'PCM-Ob2lys-tXo3-9OwTmg';
    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(encoded);
    const calculatedSignature = hmac.digest('hex');
    return crypto.timingSafeEqual(
      Buffer.from(calculatedSignature),
      Buffer.from(signature)
    );
  } catch (error) {
    console.error('Error verificando firma:', error);
    return false;
  }
};

// Función para actualizar el saldo del usuario
const updateUserBalance = async (userId, amount) => {
  try {
    const usersData = await readJSONFile(USERS_FILE);
    if (!usersData) {
      throw new Error('Error al leer la base de datos de usuarios');
    }

    const userIndex = usersData.users.findIndex(u => u.id === userId);
    if (userIndex === -1) {
      throw new Error('Usuario no encontrado');
    }

    // Actualizar saldo
    usersData.users[userIndex].balance += Number(amount);

    // Guardar cambios
    await writeJSONFile(USERS_FILE, usersData);

    return usersData.users[userIndex].balance;
  } catch (error) {
    console.error('Error actualizando saldo:', error);
    throw error;
  }
};

// Endpoint para recibir notificaciones de Bold
app.post('/api/webhook/bold', async (req, res) => {
  try {
    console.log('Webhook recibido:', req.body);
    
    // Obtener la firma del header
    const signature = req.headers['x-bold-signature'];
    if (!signature) {
      console.log('Firma no proporcionada');
      return res.status(400).json({ error: 'Firma no proporcionada' });
    }

    // Verificar la firma
    const isValidSignature = verifyBoldSignature(signature, req.body);
    if (!isValidSignature) {
      console.log('Firma inválida');
      return res.status(400).json({ error: 'Firma inválida' });
    }

    // Responder inmediatamente con 200 como requiere Bold
    res.status(200).json({ status: 'OK' });

    // Procesar el evento de manera asíncrona
    const { type, data } = req.body;
    console.log('Tipo de evento:', type);
    console.log('Datos del evento:', data);

    if (type === 'SALE_APPROVED') {
      const { payment_id, amount, metadata } = data;
      
      // Buscar la transacción en nuestra base de datos
      const transactionsData = await readJSONFile(TRANSACTIONS_FILE);
      if (!transactionsData) {
        throw new Error('Error al leer la base de datos de transacciones');
      }

      // Crear nueva transacción
      const newTransaction = {
        id: String(transactionsData.transactions.length + 1),
        boldPaymentId: payment_id,
        userId: metadata.userId,
        type: 'RECHARGE',
        amount: amount.total,
        status: 'COMPLETED',
        description: 'Recarga de saldo via Bold',
        createdAt: new Date().toISOString()
      };

      // Guardar la transacción
      transactionsData.transactions.push(newTransaction);
      await writeJSONFile(TRANSACTIONS_FILE, transactionsData);

      // Actualizar el saldo del usuario
      await updateUserBalance(metadata.userId, amount.total);
      console.log('Transacción procesada exitosamente:', newTransaction);
    }

  } catch (error) {
    console.error('Error procesando webhook:', error);
    // No enviamos respuesta de error porque ya respondimos con 200
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 