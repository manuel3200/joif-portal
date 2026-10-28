'use strict';

/**
 * Servicio de Verificación vía Bot de Telegram y Grupo Oficial
 * Conexión nativa con la API de Telegram (Zero external dependencies)
 */

class TelegramService {
  constructor({ database }) {
    this.database = database;
    this.isEnabled = false;
    this.botToken = '';
    this.groupId = '';
    this.groupLink = '';
    this.botUsername = '';
    this.isPolling = false;
    this.abortController = null;
    this.pollingPromise = null;
  }

  async init() {
    await this.reloadConfig();
  }

  async reloadConfig() {
    this.stopPolling();

    const configRows = await this.database.query(`
      SELECT key, value FROM admin_config 
      WHERE key IN (
        'telegram_verification_enabled',
        'telegram_bot_token',
        'telegram_group_id',
        'telegram_group_link',
        'telegram_bot_username'
      )
    `);

    const cfg = {};
    for (const row of configRows.rows) {
      cfg[row.key] = row.value;
    }

    this.isEnabled = cfg.telegram_verification_enabled === 'true';
    this.botToken = (cfg.telegram_bot_token || '').trim();
    this.groupId = (cfg.telegram_group_id || '').trim();
    this.groupLink = (cfg.telegram_group_link || '').trim();
    this.botUsername = (cfg.telegram_bot_username || '').trim();

    if (this.isEnabled && this.botToken) {
      this.startPolling();
    }
  }

  async testConnection({ botToken, groupId }) {
    const token = (botToken || this.botToken || '').trim();
    const group = (groupId || this.groupId || '').trim();

    if (!token) {
      return { success: false, error: 'Token de bot no proporcionado.' };
    }

    try {
      // 1. Probar getMe
      const meRes = await fetch(`https://api.telegram.org/bot${token}/getMe`, {
        method: 'GET',
        signal: AbortSignal.timeout(8000)
      });
      const meData = await meRes.json().catch(() => ({}));
      if (!meRes.ok || !meData.ok) {
        return {
          success: false,
          error: meData.description || 'El token de Telegram es inválido o no existe.'
        };
      }

      const bot = meData.result;
      const result = {
        success: true,
        bot: {
          id: bot.id,
          first_name: bot.first_name,
          username: bot.username
        }
      };

      // 2. Si se especificó groupId, verificar acceso al grupo
      if (group) {
        try {
          const chatRes = await fetch(`https://api.telegram.org/bot${token}/getChat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: group }),
            signal: AbortSignal.timeout(8000)
          });
          const chatData = await chatRes.json().catch(() => ({}));

          if (!chatRes.ok || !chatData.ok) {
            return {
              success: false,
              bot: result.bot,
              error: `El bot no tiene acceso al grupo/canal "${group}". Asegúrate de agregarlo como Administrador en tu grupo. Detalle: ${chatData.description || 'Chat not found'}`
            };
          }

          // Verificar si el bot es admin en el grupo
          const memberRes = await fetch(`https://api.telegram.org/bot${token}/getChatMember`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: group, user_id: bot.id }),
            signal: AbortSignal.timeout(8000)
          });
          const memberData = await memberRes.json().catch(() => ({}));

          result.group = {
            id: chatData.result.id,
            title: chatData.result.title || chatData.result.username || group,
            type: chatData.result.type,
            bot_status: memberData.result?.status || 'unknown'
          };
        } catch (chatErr) {
          return {
            success: false,
            bot: result.bot,
            error: `Error verificando grupo: ${chatErr.message}`
          };
        }
      }

      return result;
    } catch (err) {
      return {
        success: false,
        error: `Error de red al conectar con Telegram API: ${err.message}`
      };
    }
  }

  async checkMember(botToken, groupId, userId) {
    if (!botToken || !groupId || !userId) {
      return { isMember: false, status: 'error', reason: 'Faltan parámetros de consulta.' };
    }

    try {
      const res = await fetch(`https://api.telegram.org/bot${botToken}/getChatMember`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: groupId, user_id: Number(userId) }),
        signal: AbortSignal.timeout(7000)
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        return {
          isMember: false,
          status: 'not_found',
          reason: data.description || 'Usuario no encontrado en el grupo.'
        };
      }

      const status = data.result.status;
      // Estados válidos: creador, administrador o miembro regular
      if (['creator', 'administrator', 'member'].includes(status)) {
        return { isMember: true, status };
      }
      if (status === 'restricted' && data.result.is_member) {
        return { isMember: true, status };
      }

      return { isMember: false, status };
    } catch (err) {
      return { isMember: false, status: 'network_error', reason: err.message };
    }
  }

  async generateCode(userId, username = '') {
    // Código de 6 dígitos aleatorio
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Invalidar códigos no usados anteriores del mismo usuario para evitar acumulación
    await this.database.query(`
      UPDATE verification_tokens 
      SET is_used = 1 
      WHERE telegram_user_id = ? AND is_used = 0
    `, [String(userId)]);

    // Insertar nuevo código válido por 15 minutos
    await this.database.query(`
      INSERT INTO verification_tokens (code, telegram_user_id, telegram_username, expires_at, is_used)
      VALUES (?, ?, ?, datetime('now', '+15 minutes'), 0)
    `, [code, String(userId), username || '']);

    return code;
  }

  async verifyAndConsumeCode(code) {
    if (!code || typeof code !== 'string') {
      return { valid: false, reason: 'Código de verificación no proporcionado.' };
    }

    const cleanCode = code.trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return { valid: false, reason: 'El código de verificación debe ser de 6 dígitos numéricos.' };
    }

    const res = await this.database.query(`
      SELECT * FROM verification_tokens 
      WHERE code = ? AND is_used = 0 AND datetime(expires_at) > datetime('now')
      LIMIT 1
    `, [cleanCode]);

    if (res.rowCount === 0) {
      return {
        valid: false,
        reason: 'Código de Telegram inválido, ya utilizado o expirado. Solicita uno nuevo enviando /start al bot.'
      };
    }

    // Marcar de inmediato como usado
    await this.database.query('UPDATE verification_tokens SET is_used = 1 WHERE code = ?', [cleanCode]);

    return {
      valid: true,
      tokenData: res.rows[0]
    };
  }

  async sendMessage(chatId, text, replyMarkup = null) {
    if (!this.botToken) return;
    try {
      const payload = {
        chat_id: chatId,
        text,
        parse_mode: 'HTML'
      };
      if (replyMarkup) payload.reply_markup = replyMarkup;

      await fetch(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000)
      });
    } catch (e) {
      console.warn('[TELEGRAM-BOT] Error enviando mensaje:', e.message);
    }
  }

  async handleUserVerification(chatId, fromUser) {
    const userId = fromUser.id;
    const firstName = fromUser.first_name || 'Amigo';
    const username = fromUser.username || '';

    if (!this.groupId) {
      await this.sendMessage(
        chatId,
        `⚠️ <b>¡Hola, ${firstName}!</b>\n\nEl sistema de verificación por grupo está en mantenimiento (Grupo no configurado en el panel). Contacta al administrador.`
      );
      return;
    }

    const check = await this.checkMember(this.botToken, this.groupId, userId);

    if (!check.isMember) {
      const link = this.groupLink || `https://t.me/${this.groupId.replace('@', '')}`;
      const inlineKeyboard = {
        inline_keyboard: [
          [{ text: '👥 Unirme al Grupo Oficial', url: link }],
          [{ text: '🔄 Ya me uní (Verificar)', callback_data: 'check_member' }]
        ]
      };

      await this.sendMessage(
        chatId,
        `⚠️ <b>¡Hola, ${firstName}!</b>\n\n` +
        `Para poder generar tu código de activación y crear tu cuenta VPN gratuita, primero <b>debes estar unido a nuestra comunidad oficial</b>.\n\n` +
        `👉 <b>Paso 1:</b> Únete a nuestro grupo oficial tocando el botón abajo.\n` +
        `👉 <b>Paso 2:</b> Regresa a este chat y presiona <b>"Ya me uní"</b> o escribe <b>/start</b> para recibir tu código.`,
        inlineKeyboard
      );
      return;
    }

    // El usuario sí es miembro del grupo
    const code = await this.generateCode(userId, username);

    const inlineKeyboard = {
      inline_keyboard: [
        [{ text: '🔄 Generar Nuevo Código', callback_data: 'check_member' }]
      ]
    };

    await this.sendMessage(
      chatId,
      `🎉 <b>¡VERIFICACIÓN EXITOSA!</b>\n\n` +
      `Hola <b>${firstName}</b>, confirmamos que eres miembro de nuestra comunidad.\n\n` +
      `Tu código de verificación para la página web es:\n\n` +
      `🔑 <code>${code}</code>  <i>(Toca el número para copiar)</i>\n\n` +
      `⏳ <b>Vigencia:</b> 15 minutos (Uso único).\n` +
      `👉 Pega este código en el formulario de la página web para crear tu cuenta VPN.`,
      inlineKeyboard
    );
  }

  async handleMessage(message) {
    if (!message || !message.chat) return;
    const chatType = message.chat.type;

    // Solo atendemos chats privados (directos con el bot)
    if (chatType !== 'private') {
      if (message.text && (message.text.startsWith('/start') || message.text.startsWith('/token'))) {
        const botName = this.botUsername ? `@${this.botUsername}` : 'el bot en privado';
        await this.sendMessage(
          message.chat.id,
          `ℹ️ Para obtener tu código de verificación de forma privada, por favor escríbeme directamente a ${botName}`
        );
      }
      return;
    }

    await this.handleUserVerification(message.chat.id, message.from);
  }

  async handleCallbackQuery(cq) {
    if (!cq || !cq.from) return;
    try {
      // Responder callback para quitar el estado de carga en Telegram
      await fetch(`https://api.telegram.org/bot${this.botToken}/answerCallbackQuery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: cq.id }),
        signal: AbortSignal.timeout(5000)
      });
    } catch {}

    if (cq.data === 'check_member' && cq.message?.chat?.id) {
      await this.handleUserVerification(cq.message.chat.id, cq.from);
    }
  }

  startPolling() {
    if (this.isPolling) return;
    this.isPolling = true;
    this.abortController = new AbortController();

    console.log(`🤖 [TELEGRAM-BOT] Iniciando sondeo (polling) para bot token [${this.botToken.slice(0, 8)}...]`);

    this.pollingPromise = (async () => {
      let offset = 0;

      // Auto-detectar username del bot al arrancar si no está configurado
      try {
        const meRes = await fetch(`https://api.telegram.org/bot${this.botToken}/getMe`, {
          signal: AbortSignal.timeout(8000)
        });
        const meData = await meRes.json().catch(() => ({}));
        if (meData.ok && meData.result?.username) {
          this.botUsername = meData.result.username;
          await this.database.query(`
            INSERT INTO admin_config (key, value) VALUES ('telegram_bot_username', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
          `, [this.botUsername]);
          console.log(`🤖 [TELEGRAM-BOT] Conectado exitosamente como @${this.botUsername}`);
        }
      } catch (err) {
        console.warn('[TELEGRAM-BOT] Aviso consultando getMe:', err.message);
      }

      while (this.isPolling) {
        try {
          const res = await fetch(`https://api.telegram.org/bot${this.botToken}/getUpdates`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              offset,
              timeout: 25,
              allowed_updates: ['message', 'callback_query']
            }),
            signal: this.abortController?.signal
          });

          if (!res.ok) {
            if (res.status === 409) {
              console.warn('[TELEGRAM-BOT] 409 Conflicto: Otra instancia del bot está corriendo o webhook activo. Reintentando en 10s...');
              await new Promise((r) => setTimeout(r, 10000));
              continue;
            }
            await new Promise((r) => setTimeout(r, 4000));
            continue;
          }

          const data = await res.json();
          if (data.ok && Array.isArray(data.result)) {
            for (const update of data.result) {
              offset = update.update_id + 1;
              if (update.message) {
                await this.handleMessage(update.message);
              } else if (update.callback_query) {
                await this.handleCallbackQuery(update.callback_query);
              }
            }
          }
        } catch (err) {
          if (!this.isPolling) break;
          // Errores de timeout o red temporales: esperar 4 segundos
          await new Promise((r) => setTimeout(r, 4000));
        }
      }
    })();
  }

  stopPolling() {
    this.isPolling = false;
    if (this.abortController) {
      try {
        this.abortController.abort();
      } catch {}
      this.abortController = null;
    }
  }
}

module.exports = { TelegramService };
