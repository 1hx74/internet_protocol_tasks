const express = require('express');
const { Provider } = require('oidc-provider');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// юзер
const USERS = {
  admin: { password: 'admin', name: 'Administrator' },
};

// конфигурация клиента
const CLIENTS = [{
  client_id: 'my-client',
  client_secret: 'secret',
  redirect_uris: ['http://localhost:3000/callback'],
  response_types: ['code'],
  grant_types: ['authorization_code'],
}];

// настройка OIDC сервера
const oidc = new Provider('http://localhost:3000', {
  clients: CLIENTS,
  features: {
    devInteractions: { enabled: true },
  },
  findAccount: async (ctx, id) => {
    const user = USERS[id];
    if (!user) return undefined;
    return {
      accountId: id,
      async claims() {
        return { sub: id, name: user.name, password: user.password };
      }
    };
  },
});

// callback для клиента, получает code и меняет на токен
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.send('Нет кода авторизации');

  // Обмен кода на токен
  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', 'http://localhost:3000/callback');
  params.append('client_id', 'my-client');
  params.append('client_secret', 'secret');

  const tokenResp = await fetch('http://localhost:3000/token', {
    method: 'POST',
    body: params
  });
  const tokenJson = await tokenResp.json();

  // распаковка JWT
  const decoded = jwt.decode(tokenJson.id_token);

  res.send(`
    <h1>Вы залогинились под: ${decoded.sub}</h1>
    <p>Ваш пароль: ${decoded.password}</p>
  `);
});

app.use('/', oidc.callback());

app.listen(3000, () => {
  console.log('OIDC server + client demo running at http://localhost:3000');
});

// to open - go to http://localhost:3000/auth?client_id=my-client&response_type=code&scope=openid&redirect_uri=http://localhost:3000/callback
