const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const crypto = require("crypto");
const multer = require('multer');
const uuid = require('uuid');
const generateSecretKey = () => {
  return crypto.randomBytes(64).toString("hex");
};
// Configure multer to specify where to store uploaded images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Set the upload directory
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + '-' + file.originalname);
  },
});

const upload = multer({ storage: storage });
const SECRET_KEY = generateSecretKey();
console.log("SECRET_KEY:", SECRET_KEY);
server.use(jsonServer.bodyParser);
server.use(middlewares);
const SALT_ROUNDS = 10;
const port = 8000;

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
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

server.post("/auth/register", (req, res) => {
  const { Fname, Lname, email, password, confirmPassword, gender } = req.body;

  if (!email || !password || !Fname || !Lname || !confirmPassword || !gender) {
    res.status(400).json({ message: "All fields are required" });
    return;
  }

  const existingUser = findUserByEmail(email);

  if (existingUser) {
    res.status(400).json({ message: "Email already exists" });
    return;
  }

  bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
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
      gender,
      password: hash,
    };

    router.db.get("users").push(newUser).write();

    res.status(200).json({ message: "Signup successful" });
  });
});

server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  const user = findUserByEmail(email);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  const passwordMatch = verifyPassword(password, user.password);

  if (!passwordMatch) {
    res.status(401).json({ message: "Invalid email or password" });
    return;
  }

  const token = createToken({
    id: user.id,
    email: user.email,
    name: user.Fname + " " + user.Lname,
  });

  res.status(200).json({ token });
});

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

  bcrypt.hash(newPassword, SALT_ROUNDS, (err, hashedPassword) => {
    if (err) {
      res.status(500).json({ message: "Password hashing error" });
      return;
    }

    user.password = hashedPassword;
    router.db.write();

    res.status(200).json({ message: "Password reset successful" });
  });
});

server.post("/employee", (req, res) => {
  const { name, email, PhoneNo, Status, JobType, role } = req.body;

  if (!name || !email || !PhoneNo || !Status || !JobType || !role) {
    res.status(400).json({ message: "All fields are required" });
    return;
  }
// Get the image file from the request
// const imageFile = req.file;

// if (!imageFile) {
//   res.status(400).json({ message: "Image is required" });
//   return;
// }

// Generate the image URL based on where you store the uploaded image
// const imageUrl = `https://emp-api-v2.onrender.com/employee/${imageFile.filename}`;

// Generate a new UUID
const userId = uuid.v4(); // Generates a random UUID
  const newUser = {
    _id: userId,
    id: Date.now(),
    name,
    email,
    PhoneNo,
    Status,
    JobType,
    role,
    // image: imageUrl,
  };

  router.db.get("employee").push(newUser).write();

  res
    .status(201)
    .json({ message: "Employee created successfully", employee: newUser });
});

server.get("/employee", (req, res) => {
  const AllUsers = router.db.get("employee").value();

  if (AllUsers) {
    res.status(200).json(AllUsers);
  } else {
    res.status(404).json({ message: "No employees found" });
  }
});

server.get("/employee/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  const employee = router.db.get("employee").find({ id: postId }).value();

  if (employee) {
    res.status(200).json(employee);
  } else {
    res.status(404).json({ message: "Employee not found" });
  }
});

server.put("/employee/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  const { name, email, PhoneNo, Status, JobType, role } = req.body;

  if (!name || !email || !PhoneNo || !Status || !JobType || !role) {
    res.status(400).json({ message: "All fields are required" });
    return;
  }

  const existingEmployee = router.db
    .get("employee")
    .find({ id: postId })
    .value();

  if (!existingEmployee) {
    res.status(404).json({ message: "Employee not found" });
    return;
  }

  existingEmployee.name = name;
  existingEmployee.email = email;
  existingEmployee.PhoneNo = PhoneNo;
  existingEmployee.Status = Status;
  existingEmployee.JobType = JobType;
  existingEmployee.role = role;
  router.db.write();

  res
    .status(200)
    .json({
      message: "Employee updated successfully",
      employee: existingEmployee,
    });
});

server.delete("/employee/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  const employee = router.db.get("employee").find({ id: postId }).value();

  if (!employee) {
    res.status(404).json({ message: "Employee not found" });
    return;
  }

  router.db.get("employee").remove({ id: postId }).write();

  res.status(200).json({ message: "Employee deleted successfully" });
});

server.listen(port, () => {
  console.log(`JSON Server with authentication is running on port ${port}`);
});
