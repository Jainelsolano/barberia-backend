import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { google } from "googleapis";
import cors from "cors";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Configuración CORS para Netlify
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5500',
  'https://gentle-kleicha-a6cbc0.netlify.app', // CAMBIARÁS ESTO DESPUÉS
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const PORT = process.env.PORT || 3000;
const TOKEN_PATH = path.join(__dirname, 'tokens.json');

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

// Función para guardar tokens
function saveTokens(tokens) {
  try {
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    console.log("✅ Tokens guardados correctamente");
    return true;
  } catch (error) {
    console.error("❌ Error al guardar tokens:", error);
    return false;
  }
}

// Función para cargar tokens automáticamente
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_PATH)) {
      const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
      oAuth2Client.setCredentials(tokens);
      console.log("🔐 Tokens cargados automáticamente desde tokens.json");
      return true;
    }
  } catch (error) {
    console.error("❌ Error al cargar tokens:", error);
  }
  return false;
}

// Inicializar autenticación con tokens guardados
const tokensLoaded = loadTokens();

// Middleware para verificar autenticación con manejo de promesas
async function ensureAuthenticated(req, res, next) {
  try {
    const credentials = oAuth2Client.credentials;
    
    if (!credentials || !credentials.access_token) {
      return res.status(401).json({ 
        error: "No autenticado con Google Calendar",
        authUrl: `${process.env.REDIRECT_URI?.replace('/callback', '') || `https://${req.get('host')}`}/auth/google`
      });
    }
    
    if (credentials.expiry_date && credentials.expiry_date <= Date.now()) {
      console.log("🔄 Token expirado, refrescando...");
      
      if (!credentials.refresh_token) {
        return res.status(401).json({ 
          error: "Token expirado sin refresh_token. Re-autentica con Google.",
          authUrl: `${process.env.REDIRECT_URI?.replace('/callback', '') || `https://${req.get('host')}`}/auth/google`
        });
      }
      
      try {
        const { credentials: newCredentials } = await oAuth2Client.refreshAccessToken();
        oAuth2Client.setCredentials(newCredentials);
        saveTokens(newCredentials);
        console.log("✅ Token refrescado exitosamente");
        next();
      } catch (refreshError) {
        console.error("❌ Error al refrescar token:", refreshError);
        return res.status(401).json({ 
          error: "Error al refrescar token. Re-autentica con Google.",
          authUrl: `${process.env.REDIRECT_URI?.replace('/callback', '') || `https://${req.get('host')}`}/auth/google`
        });
      }
    } else {
      next();
    }
  } catch (error) {
    console.error("❌ Error en autenticación:", error);
    res.status(401).json({ 
      error: "Error de autenticación",
      details: error.message
    });
  }
}

// LOGIN
app.get("/auth/google", (req, res) => {
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/calendar"],
    prompt: "consent"
  });
  res.redirect(url);
});

// CALLBACK
app.get("/auth/google/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) {
      throw new Error("No se recibió código de autorización");
    }
    
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    saveTokens(tokens);
    
    console.log("✅ Autenticación exitosa con Google Calendar");
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>Autenticación Exitosa</title>
          <style>
            body {
              font-family: system-ui;
              text-align: center;
              padding: 2rem;
              background: #0a0a0a;
              color: #f0f0f0;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              margin: 0;
            }
            .container {
              max-width: 500px;
              padding: 2rem;
              background: #111;
              border-radius: 16px;
              border: 1px solid rgba(212, 175, 55, 0.3);
            }
            h2 { color: #D4AF37; }
            button {
              background: #D4AF37;
              color: #0a0a0a;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              font-weight: bold;
              cursor: pointer;
              margin-top: 20px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>✅ ¡Autenticación Exitosa!</h2>
            <p>Barbería conectada correctamente con Google Calendar.</p>
            <p>Ya puedes cerrar esta ventana y usar el sistema de citas.</p>
            <button onclick="window.close()">Cerrar ventana</button>
            <p style="font-size: 0.8rem; color: #aaa; margin-top: 20px;">
              Esta ventana se cerrará automáticamente en 5 segundos...
            </p>
          </div>
          <script>setTimeout(() => window.close(), 5000);</script>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("❌ Error en callback:", error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
        <head><meta charset="UTF-8"><title>Error de Autenticación</title></head>
        <body style="font-family: system-ui; text-align: center; padding: 2rem; background: #0a0a0a; color: #f0f0f0;">
          <h2 style="color: #e74c3c;">❌ Error al autenticar</h2>
          <p>${error.message}</p>
          <a href="/auth/google" style="color: #D4AF37;">Intentar de nuevo</a>
        </body>
      </html>
    `);
  }
});

// Verificar autenticación
app.get("/auth/status", (req, res) => {
  const credentials = oAuth2Client.credentials;
  const isAuthenticated = credentials && credentials.access_token;
  
  res.json({
    authenticated: isAuthenticated,
    hasRefreshToken: !!(credentials && credentials.refresh_token),
    expiryDate: credentials?.expiry_date || null
  });
});

// Función para obtener calendario
function getCalendar() {
  return google.calendar({ version: "v3", auth: oAuth2Client });
}

// Generar horas ocupadas
function generarHorasOcupadas(eventos, fecha) {
  const horasOcupadas = [];
  
  eventos.forEach(evento => {
    if (evento.start?.dateTime && !evento.summary?.toLowerCase().includes("no disponible")) {
      const inicio = new Date(evento.start.dateTime);
      const horaStr = `${inicio.getHours().toString().padStart(2, '0')}:${inicio.getMinutes().toString().padStart(2, '0')}`;
      horasOcupadas.push(horaStr);
    }
  });
  
  return horasOcupadas;
}

// ENDPOINT: GET /disponibilidad
app.get("/disponibilidad", ensureAuthenticated, async (req, res) => {
  try {
    const { fecha } = req.query;
    
    if (!fecha) {
      return res.status(400).json({ error: "Se requiere parámetro fecha" });
    }
    
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
      return res.status(400).json({ error: "Formato de fecha inválido. Use YYYY-MM-DD" });
    }
    
    console.log(`🔍 Verificando disponibilidad para: ${fecha}`);
    
    const calendar = getCalendar();
    const timeZone = "America/Mexico_City";
    const startOfDay = new Date(`${fecha}T00:00:00`);
    const endOfDay = new Date(`${fecha}T23:59:59`);
    
    const eventos = await calendar.events.list({
      calendarId: "primary",
      timeMin: startOfDay.toISOString(),
      timeMax: endOfDay.toISOString(),
      singleEvents: true,
      orderBy: "startTime",
      timeZone: timeZone
    });
    
    const diaBloqueado = eventos.data.items.some(evento => 
      evento.summary?.toLowerCase().includes("no disponible")
    );
    
    if (diaBloqueado) {
      console.log(`🚫 Día ${fecha} bloqueado`);
      return res.json({ 
        disponible: false,
        mensaje: "Este día no está disponible para agendar citas"
      });
    }
    
    const horasOcupadas = generarHorasOcupadas(eventos.data.items, fecha);
    
    console.log(`✅ Día disponible. Horas ocupadas: ${horasOcupadas.join(', ') || 'ninguna'}`);
    
    res.json({
      disponible: true,
      horasOcupadas: horasOcupadas
    });
    
  } catch (error) {
    console.error("❌ Error en /disponibilidad:", error);
    res.status(500).json({ 
      error: "Error al consultar disponibilidad",
      details: error.message 
    });
  }
});

// ENDPOINT: POST /crear-cita
app.post("/crear-cita", ensureAuthenticated, async (req, res) => {
  try {
    const { name, date, time, phone } = req.body;
    
    if (!name || !date || !time || !phone) {
      return res.status(400).json({ error: "Faltan campos requeridos" });
    }
    
    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: "El nombre debe tener entre 2 y 100 caracteres" });
    }
    
    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) {
      return res.status(400).json({ error: "Formato de teléfono inválido" });
    }
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const selectedDate = new Date(date);
    
    if (selectedDate < today) {
      return res.status(400).json({ error: "No se pueden agendar citas en fechas pasadas" });
    }
    
    const [hora, minuto] = time.split(':').map(Number);
    if (hora < 9 || hora > 20 || (hora === 20 && minuto > 0)) {
      return res.status(400).json({ error: "Horario no válido. Las citas son de 9:00 a 20:00" });
    }
    
    if (minuto !== 0 && minuto !== 30) {
      return res.status(400).json({ error: "Las citas solo se pueden agendar cada 30 minutos" });
    }
    
    console.log(`📝 Creando cita: ${name} - ${date} ${time}`);
    
    const calendar = getCalendar();
    const timeZone = "America/Mexico_City";
    
    const inicio = new Date(`${date}T${time}:00`);
    const fin = new Date(inicio.getTime() + 30 * 60 * 1000);
    
    const eventosExistentes = await calendar.events.list({
      calendarId: "primary",
      timeMin: inicio.toISOString(),
      timeMax: fin.toISOString(),
      singleEvents: true,
      timeZone: timeZone
    });
    
    const citasExistentes = eventosExistentes.data.items.filter(evento => 
      !evento.summary?.toLowerCase().includes("no disponible")
    );
    
    if (citasExistentes.length > 0) {
      console.log(`⚠️ Horario ${time} ya ocupado`);
      return res.status(409).json({ error: "Este horario ya está ocupado" });
    }
    
    const startOfDay = new Date(`${date}T00:00:00`);
    const endOfDay = new Date(`${date}T23:59:59`);
    
    const eventosDia = await calendar.events.list({
      calendarId: "primary",
      timeMin: startOfDay.toISOString(),
      timeMax: endOfDay.toISOString(),
      singleEvents: true,
      timeZone: timeZone
    });
    
    const diaBloqueado = eventosDia.data.items.some(evento =>
      evento.summary?.toLowerCase().includes("no disponible")
    );
    
    if (diaBloqueado) {
      console.log(`🚫 Día ${date} bloqueado`);
      return res.status(400).json({ error: "Este día no está disponible para citas" });
    }
    
    const event = {
      summary: `✂️ Cita - ${name}`,
      description: `Cliente: ${name}\nTeléfono: ${phone}\nReservado desde la web el ${new Date().toLocaleString('es-MX')}`,
      start: {
        dateTime: inicio.toISOString(),
        timeZone: timeZone
      },
      end: {
        dateTime: fin.toISOString(),
        timeZone: timeZone
      },
      reminders: {
        useDefault: false,
        overrides: [
          { method: "email", minutes: 60 },
          { method: "popup", minutes: 30 }
        ]
      }
    };
    
    const result = await calendar.events.insert({
      calendarId: "primary",
      resource: event
    });
    
    console.log(`✅ Cita creada: ${result.data.htmlLink}`);
    
    res.json({ 
      success: true, 
      message: "Cita creada exitosamente",
      eventId: result.data.id,
      eventLink: result.data.htmlLink
    });
    
  } catch (error) {
    console.error("❌ Error en /crear-cita:", error);
    res.status(500).json({ 
      error: "Error al crear la cita",
      details: error.message 
    });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    authenticated: !!(oAuth2Client.credentials && oAuth2Client.credentials.access_token),
    timestamp: new Date().toISOString()
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`\n🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`🔐 Autenticar con Google: http://localhost:${PORT}/auth/google`);
  
  if (tokensLoaded) {
    console.log("✅ Sistema autenticado con Google Calendar");
  } else {
    console.log("⚠️  No hay autenticación. Visita /auth/google para conectar con Google Calendar\n");
  }
});
