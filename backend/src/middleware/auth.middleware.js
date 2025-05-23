import jwt from "jsonwebtoken";
import { db } from "../libs/db.js";
export const authMiddleWare = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({
        message: "Unauthorized - No token provided",
      });
    }
    let decoded;

    decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await db.user.findUnique({
      where: {
        id: decoded.id,
      },
      select: {
        id: true,
        image: true,
        name: true,
        email: true,
        role: true,
      },
    });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    req.user = user;
    next();
  } catch (err) {
    console.log("error checking user ",err)
    return res.status(401).json({
      message: "Unauthorized - Invalid token",
    });
  }
};
