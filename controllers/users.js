const prisma = require("../prisma/migrations/prisma-client");
const brypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const login = async (req, res, next) => {
  const { email, password} = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Заполните поля!" });


  const user = await prisma.user.findFirst({
    where: { email },
  });

  const isPasswordCorrect =
    user && (await brypt.compare(password, user.password));
  const secret = process.env.JWT_SECRET
  
  if (user && isPasswordCorrect) {
    res.status(200).json({ id: user.id, email: user.email, jwt: jwt.sign({id:user.id, name: user.name }, secret, {expiresIn:"30d"}) });
  } else {
    return res.status(400).json({ message: "Неверно введен логин или пароль" });
  }
};

const register = async (req, res, next) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: "Заполните поля!" });
  }

  const registeredUser = await prisma.user.findFirst({
    where: {
      email,
    },
  });

  if (registeredUser)
    return res.status(400).json({ message: "Пользователь уже существует" });

  const salt = await brypt.genSalt(10);
  const hashedPassword = await brypt.hash(password, salt);

  const user = await prisma.user.create({
    data: {
      email,
      name,
      password: hashedPassword,
    },
  });

  const secret = process.env.JWT_SECRET;

  if (user && secret) {
    res.status(201).json({
      id: user.id,
      email: user.email,
      name,
      token: jwt.sign({ id: user.id }, secret, { expiresIn: "30d" }),
    });
  } else {
    res.status(400).json({ message: "Не удалость создать пользователя" });
  }
};

const current = async (req, res, next) => {
  return res.status(200).json(req.user)
};

module.exports = { login, register, current };
