const jwt = require("jsonwebtoken");
const prisma = require("../prisma/migrations/prisma-client");

const auth = async (req, res, next) => {
  try {
    let token = req.headers.authorization?.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id,
      },
    });

    if (!user) {
      return res.status(401).json({ message: "Пользователь не найден" });
    }

    req.user = user;

    next();
  } catch (err) {
    res.status(401).json({ messege: "Не авторизован" });
  }
};

module.exports = { auth };
