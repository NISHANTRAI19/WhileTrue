import bcrypt from "bcryptjs";

import { UserRole } from "../../prisma/generated/prisma/index.js";
import jwt from "jsonwebtoken";
import { db } from "../libs/db.js";

export const register = async (req, res) => {


  try {
  const { email, password, name } = req.body;

    const exisitingUser = await db.user.findUnique({
      where: {
        email,
      },
    });

    if (exisitingUser) {
      return res.status(400).json({
        error: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await db.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        role: UserRole.USER,
      },
    });

    const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("jwt", token, {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV !== "development",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    res.status(201).json({
      message: "User created successfully",
      User: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        image: newUser.image,
      },
    });
  } catch (error) {
    console.error("Error creating user ", error);
    res.status(500).json({
      error: "Error creating User",
    });
  }
};

export const login = async (req, res) => {

  try {
  const {  email,password } = req.body;
    const user = await db.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(401).json({
        error: "User not found",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch){
      return res.status(401).json({
        error:"Invalid Credentials"
      })
    }

    const token = jwt.sign({id:user.id}, process.env.JWT_SECRET,{
      expiresIn:"7d"
    })

    res.cookie("jwt",token,{
      httpOnly:true,
      sameSite:"strict",
      secure:process.env.NODE_ENV!== "development",
      maxAge: 1000*60*60*24*7
    })

    return res.status(201).json({
      success:true,
      message:"User logged in Succesfully",
      User:{
        id:user.id,
        name:user.name,
        email:user.email,
        image:user.image,
        role:user.role
      }
    })
  } catch (error) {
    console.log("Error in Login ", error)
    res.status(401).json({
      message:"Error logging in"
    })
  }
};

export const logout = async (req, res) => {
  try{
    res.clearCookie("jwt",{
      httpOnly:true,
      sameSite:"strict",
      secure: process.env.NODE_ENV !== "development",

    })

    return res.status(200).json({
      message:"User logged Out succesfully",
      success:true
    })
  }
  catch(error){
    console.error("error logging out user", error)
    res.status(500).json({
      error:"ERROR LOGGING OUT USER"
    })
  }
};

export const check = async (req, res) => {
  try{
    res.status(200).json({
      success:true,
      message:"User checked succesfullu",
      user:req.user
    })
  }
  catch(error){
    console.error("error checking user")
    return res.status(500).json({
      message:"Error checking user"
    })
  }
};
