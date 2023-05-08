const { prisma } = require('../prisma/prisma-client');
const brypt = require('bсrypt');
const jwt = require('jsonwebtoken');
/**
@route Post /api/user/login
@desc логин
@access Public
 **/
const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Пожалуйста заполните обязательное поле' });
  }
  const user = await prisma.user.findFirst({
    where: {
      email,
    },
  });

  const isPasswordCorrect = user && (await brypt.compare(password, user.password));

  if (user && isPasswordCorrect) {
    res.status(200).json({
      id: user.id,
      email: user.email,
      name: user.name,
    });
  } else {
    return res.status(400).json({ message: 'Неверно введен логин или пароль' });
  }
};

/**
 *
 *@route Post /api/user/reqister
 *@desc Регистрация
 *@access Public
 **/
const register = async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: 'Заполните все поля' });
  }

  const registered = await prisma.user.findFirst({
    where: {
      email,
    },
  });
  if (registered) {
    return res.status(400).json({ message: 'Пользователь, с таким email уже зарегестрирован' });
  }
  const salt = await brypt.genSalt(10);
  const haschedPassword = await brypt.hash(password, salt);
  const user = await prisma.user.create({
    data: {
      email,
      password: haschedPassword,
      name,
    },
  });

  const secret = process.env.JNV_SECRET;

  if (user && secret) {
    res.status(201).json({
      id: user.id,
      email: user.email,
      name: user,
      token: jwt.sign({ id: user.id }, secret, { expiresIn: '30d' }),
    });
  } else {
    return res.status(400).json({ message: 'Не удалось создать пользователя' });
  }
};
const current = async (req, res) => {
  res.send('current');
};

module.exports = {
  login,
  register,
  current,
};
