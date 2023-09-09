// const jsonServer = require('json-server');
// const server = jsonServer.create();
// const router = jsonServer.router('db.json');
// const middlewares = jsonServer.defaults();

// server.use(middlewares);
// server.use(router);

// server.listen(3000, () => {
//   console.log('JSON Server is running');
// });

const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const crypto = require('crypto');

// what is crypto module?
// crypto module ke sath ham password ko hash kar sakte hai or use database me store kar sakte hai.

//With cryptography in Node.js, you can hash passwords and store them in the database so that data cannot be converted to plain text after it is hashed; it can only be verified. When malicious actors get ahold of your database, they cannot decode the encrypted information.

const generateSecretKey = () => {
  return crypto.randomBytes(64).toString('hex');
};

const SECRET_KEY = generateSecretKey();
console.log('SECRET_KEY:', SECRET_KEY);
server.use(jsonServer.bodyParser);
server.use(middlewares);
const SALT_ROUNDS = 10;
const port = 8000;

// const SECRET_KEY =
//   "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTY4NjQyODg2MSwiaWF0IjoxNjg2NDI4ODYxfQ.bUtjAJH274x2Gv0irh2A0a_tPS9YWvdet0e-TVQ6hBE";

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
}

function isAuthenticated({ email, password }) {
  const users = router.db.get("users").value();
  return users.some(
    (user) => user.email === email && user.password === password
  );
}

function isExistingUser(email) {
  const users = router.db.get("users").value();
  return users.some((user) => user.email === email);
}

function findUserByEmail(email) {
  return router.db.get("users").find({ email }).value();
}

function verifyPassword(password, hashedPassword) {
  return bcrypt.compareSync(password, hashedPassword);
}

// user signup
server.post("/auth/register", (req, res) => {
  const {
    Fname,
    Lname,
    email,
    password,
    confirmPassword,
    // phoneNumber,
    // DOB,
    gender,
  } = req.body;

  if (!email) {
    res.status(400).json({ message: "Email are required" });
    return;
  }
  if (!password) {
    res.status(400).json({ message: "Password are required" });
    return;
  }
  if (!Fname) {
    res.status(400).json({ message: "First name are required" });
    return;
  }
  if (!Lname) {
    res.status(400).json({ message: "Last name are required" });
    return;
  }
  if (!confirmPassword) {
    res.status(400).json({ message: "Confirm password are required" });
    return;
  }
  if (password !== confirmPassword) {
    res
      .status(400)
      .json({ message: "Password and confirmPassword do not match" });
    return;
  }
  if (!gender) {
    res.status(400).json({ message: "gender are required" });
    return;
  }


  // if ( !phoneNumber) {
  //   res.status(400).json({ message: 'Phone number are required' });
  //   return;
  // }

  // const phoneRegex = /^\d{10}$/;
  // if (!phoneNumber.toString().match(phoneRegex)) {
  //   res
  //     .status(400)
  //     .json({ message: "Phone number are required. Expected 10-digit number" });
  //   return;
  // }
  // // Validate DOB format (MM-DD-YYYY)
  // const dobRegex = /^\d{2}-\d{2}-\d{4}$/;
  // if (!DOB.match(dobRegex)) {
  //   res.status(400).json({ message: "DOB are required" });
  //   return;
  // }

  // if ( !DOB) {
  //   res.status(400).json({ message: 'DOB are required' });
  //   return;
  // }


  const existingUser = findUserByEmail(email);

  if (existingUser) {
    res.status(400).json({ message: "Email already exists" });
    return;
  }
  // console.log("USERNOTFOUND", existingUser);
  // if (isExistingUser(email)) {
  //   res.status(400).json({ message: 'User already exists' });
  //   return;
  // }

  // Hash the password
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      res.status(500).json({ message: "Failed to create user" });
      return;
    }

    const newUser = {
      id: Date.now(),
      Fname,
      Lname,
      email,
      confirmPassword: hash,
      // phoneNumber,
      // DOB,
      gender,
      password: hash, // Store the hashed password
    };
    console.log("USERINFO", newUser);
    router.db.get("users").push(newUser).write();

    // const token = createToken({ id: newUser.id, email, name });
    res.status(200).json(JSON.parse( {message: "Signup successful"} ));

  });
});

// user login
server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }
  if (!email) {
    res.status(400).json({ message: "Email  are required" });
    return;
  }
  if (!password) {
    res.status(400).json({ message: "Password are required" });
    return;
  }

  const user = findUserByEmail(email);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  const passwordMatch = verifyPassword(password, user.password);

  if (!passwordMatch) {
    res.status(401).json({ message: "Invalid password" });
    return;
  }
  if (!email) {
    res.status(401).json({ message: "Invalid email" });
    return;
  }

  const token = createToken({
    id: user.id,
    email: user.email,
    name: user.name,
  });
  // Show API token and user data in the console
  console.log("API Token:", token);

  res.status(200).json({ token});
});

// user reset password
server.post("/auth/reset-password", (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    res.status(400).json({ message: "Email and new password are required" });
    return;
  }

  const user = findUserByEmail(email);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  // Hash the new password
  bcrypt.hash(newPassword, SALT_ROUNDS, (err, hashedPassword) => {
    if (err) {
      res.status(500).json({ message: "Password hashing error" });
      return;
    }

    // Update the user's password
    user.password = hashedPassword;
    router.db.write();

    res.status(200).json({ message: "Password reset successful" });
  });
});

// posts POST method
server.post("/posts", (req, res) => {
  const { title, content } = req.body;

  if (!title || !content) {
    res.status(400).json({ message: "Title and content are required" });
    return;
  }

  const newPost = {
    id: Date.now(),
    title,
    content,
  };

  router.db.get("posts").push(newPost).write();

  res.status(201).json({ message: "Post created successfully", post: newPost });
});

// get All posts
server.get("/posts", (req, res) => {
  // const postId = parseInt(req.params.id);
  const post = router.db.get("posts").value();

  if (post) {
    res.status(200).json(post);
  } else {
    res.status(404).json({ message: "Post not found" });
  }
});

// get post by id
server.get("/posts/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  const post = router.db.get("posts").find({ id: postId }).value();

  if (post) {
    res.status(200).json(post);
  } else {
    res.status(404).json({ message: "Post not found" });
  }
});

// update post
server.put("/posts/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  const { title, content } = req.body;

  if (!title || !content) {
    res.status(400).json({ message: "Title and content are required" });
    return;
  }

  const existingPost = router.db.get("posts").find({ id: postId }).value();

  if (!existingPost) {
    res.status(404).json({ message: "Post not found" });
    return;
  }

  existingPost.title = title;
  existingPost.content = content;
  router.db.write();

  res
    .status(200)
    .json({ message: "Post updated successfully", post: existingPost });
});

server.use((req, res, next) => {
  if (
    req.originalUrl === "/auth/login" ||
    req.originalUrl === "/auth/register" ||
    req.originalUrl === "/auth/reset-password"
  ) {
    next();
  } else {
    const token = req.headers.authorization?.split("Bearer ")[1];
    try {
      jwt.verify(token, SECRET_KEY);
      next();
    } catch {
      res.status(401).json({ message: "Unauthorized" });
    }
  }
});

server.use(router);

server.listen(port, () => {
  console.log(`JSON Server with authentication is running ${port}`);
});
