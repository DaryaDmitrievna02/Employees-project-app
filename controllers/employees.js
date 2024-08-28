const prisma = require("../prisma/migrations/prisma-client");

const all = async (req, res) => {
  try {
    const employees = await prisma.employee.findMany();

    res.status(200).json(employees);
  } catch (err) {
    res.status(500).json({ message: "Не удалось получить сотрудников " });
  }
};

const add = async (req, res) => {
  try {
    const data = req.body;


    if (!data.firstName || !data.lastName || !data.address || !data.age)
      return res.status(400).json({ message: "Все поля обязательны" });

    const employee = await prisma.employee.create({
      data: {
        ...data,
        userId: req.user.id,
      },
    });

    res.status(200).json(employee);
  } catch (err) {
    res.status(500).json({ message: "Что-то пошло не так " });
  }
};

const employee = async (req, res) => {
  const { id } = req.params;

  try {
    const employee = await prisma.employee.findUnique({
      where: { id },
    });

    res.status(200).json(employee);
  } catch (err) {
    res.status(500).json({ message: "Не удалось получть сотрудника" });
  }
};

const remove = async (req, res) => {
  const { id } = req.body;

  try {
    await prisma.employee.delete({
      where: {
        id,
      },
    });

    res.status(204).json("OK");
  } catch (err) {
    res.status(400).json({ message: "Не удалось удалить " });
  }
};

const edit = async (req, res) => {
  const data = req.body;
  const id = data.id;

  try {
    await prisma.employee.update({
      where: {
        id,
      },
      data,
    });

    res.status(204).json("OK");
  } catch (err) {
    res.status(500).json({ message: "Не удалось редактировать сотружника" });
  }
};

module.exports = { all, add, employee, remove, edit };
