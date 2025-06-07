const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");
require("dotenv").config();

const url = process.env.MONGO_URL; // To get the MongoDB URL we have to config dotenv file as it is an environment variable

let client; // This variable will estublish the connection to MongoDB

async function connectClient() {
  if (!client) {
    client = new MongoClient(url);
    await client.connect();
  }
}

const signup = async (req, res,next) => {
  const { username, password, email } = req.body;
  try {
    await connectClient();
    const db = client.db("Spryzen");
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ email });
    if (user) {
      const error = new Error("User already exists");
      error.statusCode = 400;
      return next(error);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = {
      username,
      email,
      password: hashedPassword,
    };
    const result = await usersCollection.insertOne(newUser);
    const token = jwt.sign(
      { id: result.insertedId },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "3h" }
    );
    res.json({ token, userId: result.insertedId });
  } catch (error) {
    // console.error("Error during signup:", error.message);
    // res.status(500).send({ message: "Internal server error" });
    next(error); // Pass error to middleware
  }
};

const login = async (req, res,next) => {
  const { email, password } = req.body;
  try {
    await connectClient();
    const db = client.db("Spryzen");
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ email });
    if (!user) {
      // return res.status(400).json({message: "Invalid credentials!"});
      const error = new Error("Invalid credentials!");
      error.statusCode = 400;
      return next(error);
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      const error = new Error("Invalid credentials!");
      error.statusCode = 400;
      return next(error);
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "3h",
    });
    res.json({ token, userId: user._id });
  } catch (error) {
    // console.error("Error during login:", error.message);
    // res.status(500).send({ message: "Internal server error" });
    next(error); // Pass error to middleware
  }
};

const logout = async (req, res,next) => {
  // In a stateless JWT system, logout is typically handled on the client
  // This endpoint exists mostly for frontend consistency
  try {
    res.clearCookie("token"); // if you ever use cookies
    return res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    // console.error("Error during logout:", error.message);
    // res.status(500).send({ message: "Internal server error" });
    next(error);
  }
};

module.exports = { signup, login, logout };
